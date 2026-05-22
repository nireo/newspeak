use super::User;
use crate::{
    local_store::{LocalStorage, PeerIdentityStoreResult},
    newspeak::{
        self, AckOfflineMessages, ClientMessage, EncryptedMessage, JoinResponse, ServerMessage,
        client_message, newspeak_client::NewspeakClient, server_message,
    },
    pqxdh::{KeyExchangeUser, PQXDHInitMessage},
    ratchet::{RatchetMessage, RatchetState},
    verification,
};
use anyhow::{Result, anyhow};
use prost_types::Timestamp;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Padding, Paragraph, Wrap},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use x25519_dalek as x25519;

enum TuiInboundEvent {
    Message(ServerMessage),
    StreamError(String),
    StreamClosed,
}

#[derive(Clone, Copy)]
enum TuiLineKind {
    System,
    Incoming,
    Outgoing,
}

struct TuiChatLine {
    timestamp: i64,
    sender: String,
    content: String,
    kind: TuiLineKind,
}

struct TuiAppState {
    username: String,
    local_identity: [u8; 32],
    active_peer: Option<String>,
    active_ratchet: Option<RatchetState>,
    conversations: Vec<String>,
    selected_conversation: usize,
    unread_counts: HashMap<String, usize>,
    messages: Vec<TuiChatLine>,
    input: String,
    status: String,
    safety_number: Option<String>,
    joined: bool,
    should_quit: bool,
}

impl TuiAppState {
    fn new(username: String, active_peer: Option<String>, local_identity: [u8; 32]) -> Self {
        Self {
            username,
            local_identity,
            active_peer,
            active_ratchet: None,
            conversations: Vec::new(),
            selected_conversation: 0,
            unread_counts: HashMap::new(),
            messages: Vec::new(),
            input: String::new(),
            status: "Connecting to server...".to_string(),
            safety_number: None,
            joined: false,
            should_quit: false,
        }
    }

    fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    fn ensure_conversation(&mut self, peer: &str) {
        if !self.conversations.iter().any(|p| p == peer) {
            self.conversations.push(peer.to_string());
            self.conversations.sort();
        }

        if let Some(active) = self.active_peer.as_ref()
            && let Some(index) = self.conversations.iter().position(|p| p == active)
        {
            self.selected_conversation = index;
        }
    }

    fn selected_peer(&self) -> Option<String> {
        self.conversations.get(self.selected_conversation).cloned()
    }

    fn move_selection_up(&mut self) {
        if self.conversations.is_empty() {
            return;
        }

        if self.selected_conversation == 0 {
            self.selected_conversation = self.conversations.len().saturating_sub(1);
        } else {
            self.selected_conversation = self.selected_conversation.saturating_sub(1);
        }
    }

    fn move_selection_down(&mut self) {
        if self.conversations.is_empty() {
            return;
        }

        self.selected_conversation = (self.selected_conversation + 1) % self.conversations.len();
    }

    fn push_line(&mut self, timestamp: i64, sender: String, content: String, kind: TuiLineKind) {
        self.messages.push(TuiChatLine {
            timestamp,
            sender,
            content,
            kind,
        });
    }

    fn push_system_line(&mut self, timestamp: i64, content: impl Into<String>) {
        self.push_line(
            timestamp,
            "system".to_string(),
            content.into(),
            TuiLineKind::System,
        );
    }

    async fn refresh_tui_conversations(
        &mut self,
        storage: &LocalStorage,
        username: &str,
    ) -> Result<()> {
        let previously_selected = self.selected_peer();
        let mut conversations = storage.get_user_conversations(username).await?;
        if let Some(active) = self.active_peer.as_ref()
            && !conversations.iter().any(|peer| peer == active)
        {
            conversations.push(active.clone());
        }

        conversations.sort();
        self.conversations = conversations;

        if self.conversations.is_empty() {
            self.selected_conversation = 0;
            return Ok(());
        }

        if let Some(active) = self.active_peer.as_ref()
            && let Some(index) = self.conversations.iter().position(|peer| peer == active)
        {
            self.selected_conversation = index;
            return Ok(());
        }

        if let Some(selected) = previously_selected
            && let Some(index) = self.conversations.iter().position(|peer| peer == &selected)
        {
            self.selected_conversation = index;
            return Ok(());
        }

        if self.selected_conversation >= self.conversations.len() {
            self.selected_conversation = self.conversations.len().saturating_sub(1);
        }

        Ok(())
    }

    async fn activate_tui_conversation(
        &mut self,
        storage: &LocalStorage,
        username: &str,
        peer: &str,
    ) -> Result<()> {
        self.active_peer = Some(peer.to_string());
        self.active_ratchet = storage.get_conversation(username, peer).await?;
        self.messages = load_tui_history(storage, username, peer).await?;
        self.unread_counts.remove(peer);

        self.ensure_conversation(peer);
        self.refresh_tui_conversations(storage, username).await?;

        self.safety_number = None;
        if let Some(peer_identity) = storage.get_peer_identity(username, peer).await? {
            if !peer_identity.verified {
                self.safety_number = Some(verification::safety_number_string(
                    &self.local_identity,
                    &peer_identity.identity_key,
                ));
            }
        }

        self.set_status(format!("active conversation: {}", peer));

        Ok(())
    }
}

async fn load_tui_history(
    storage: &LocalStorage,
    username: &str,
    peer: &str,
) -> Result<Vec<TuiChatLine>> {
    let messages = storage.get_conversation_messages(username, peer).await?;
    Ok(messages
        .into_iter()
        .map(|message| {
            let (sender, kind) = if message.is_sender {
                (username.to_string(), TuiLineKind::Outgoing)
            } else {
                (peer.to_string(), TuiLineKind::Incoming)
            };
            TuiChatLine {
                timestamp: message.timestamp,
                sender,
                content: message.content,
                kind,
            }
        })
        .collect())
}

fn byte_index_for_char(s: &str, char_index: usize) -> usize {
    if char_index == 0 {
        return 0;
    }

    s.char_indices()
        .nth(char_index)
        .map(|(idx, _)| idx)
        .unwrap_or(s.len())
}

fn render_ratatui_chat(frame: &mut ratatui::Frame<'_>, app: &TuiAppState) {
    let panel_style = Style::default().bg(Color::Reset).fg(Color::White);
    let muted_style = Style::default().fg(Color::Gray).add_modifier(Modifier::DIM);
    let border_style = Style::default().fg(Color::DarkGray);
    let key_style = Style::default().fg(Color::White).add_modifier(Modifier::BOLD);
    let warn_style = Style::default().fg(Color::Yellow);

    frame.render_widget(Block::default().style(panel_style), frame.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(2)])
        .margin(1)
        .split(frame.area());

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(78), Constraint::Percentage(22)])
        .split(chunks[0]);

    let safety_height = if app.safety_number.is_some() { 4u16 } else { 0u16 };
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(safety_height),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(body_chunks[0]);

    if let Some(safety_number) = &app.safety_number {
        let safety_block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(border_style)
            .padding(Padding::new(1, 1, 0, 0));
        let safety_text = vec![
            Line::from(Span::styled("Safety number:", warn_style)),
            Line::from(Span::styled(safety_number.as_str(), muted_style)),
        ];
        let safety_panel = Paragraph::new(safety_text)
            .style(panel_style)
            .wrap(Wrap { trim: false })
            .block(safety_block);
        frame.render_widget(safety_panel, left_chunks[0]);
    }

    let max_lines = usize::from(left_chunks[1].height.saturating_sub(1));
    let start = app.messages.len().saturating_sub(max_lines);
    let mut message_lines = Vec::new();
    for message in app.messages.iter().skip(start) {
        let sender_style = match message.kind {
            TuiLineKind::System => muted_style,
            TuiLineKind::Incoming => key_style,
            TuiLineKind::Outgoing => Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::ITALIC),
        };
        let body_style = match message.kind {
            TuiLineKind::System => muted_style,
            _ => Style::default().fg(Color::White),
        };
        message_lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", super::format_timestamp(message.timestamp)),
                muted_style,
            ),
            Span::styled(format!("{}: ", message.sender), sender_style),
            Span::styled(message.content.as_str(), body_style),
        ]));
    }
    if message_lines.is_empty() {
        message_lines.push(Line::from(Span::styled(
            "No messages yet. Use /init <username> to start a conversation.",
            muted_style,
        )));
    }

    let message_panel = Paragraph::new(message_lines)
        .style(panel_style)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .style(panel_style)
                .padding(Padding::new(1, 1, 0, 0)),
        );

    let input_block = Block::default()
        .style(panel_style)
        .borders(Borders::TOP)
        .border_style(border_style)
        .padding(Padding::new(1, 1, 0, 0));
    let input_inner = input_block.inner(left_chunks[2]);
    let input_width = usize::from(input_inner.width);
    let input_chars = app.input.chars().count();
    let visible_chars = input_width.saturating_sub(1);
    let start_char = input_chars.saturating_sub(visible_chars);
    let start_byte = byte_index_for_char(&app.input, start_char);
    let visible_input = &app.input[start_byte..];

    let input_panel = Paragraph::new(visible_input)
        .style(panel_style)
        .block(input_block);

    let items: Vec<ListItem<'_>> = if app.conversations.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "No conversations",
            muted_style,
        )))]
    } else {
        app.conversations
            .iter()
            .map(|peer| {
                let is_active = app.active_peer.as_deref() == Some(peer.as_str());
                let unread = app.unread_counts.get(peer).copied().unwrap_or(0);
                let mut spans = vec![if is_active {
                    Span::styled("> ", key_style)
                } else {
                    Span::raw("  ")
                }];
                spans.push(Span::styled(peer.as_str(), Style::default().fg(Color::White)));
                if unread > 0 {
                    spans.push(Span::raw(" "));
                    spans.push(Span::styled(format!("({})", unread), key_style));
                }
                ListItem::new(Line::from(spans))
            })
            .collect()
    };

    let sidebar = List::new(items)
        .style(panel_style)
        .highlight_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::LEFT)
                .style(panel_style)
                .border_style(border_style)
                .padding(Padding::new(1, 1, 1, 1)),
        );
    let mut list_state = ListState::default();
    if !app.conversations.is_empty() {
        list_state.select(Some(
            app.selected_conversation
                .min(app.conversations.len().saturating_sub(1)),
        ));
    }

    let connection = if app.joined { "joined" } else { "joining..." };
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("Status: ", key_style),
        Span::styled(
            format!("{} | {} | {}", app.username, connection, app.status),
            muted_style,
        ),
        Span::raw("  "),
        Span::styled("up/down", key_style),
        Span::styled(" select", muted_style),
        Span::raw("  "),
        Span::styled("enter", key_style),
        Span::styled(" send/switch", muted_style),
        Span::raw("  "),
        Span::styled("tab", key_style),
        Span::styled(" open", muted_style),
        Span::raw("  "),
        Span::styled("ctrl+c", key_style),
        Span::styled(" quit", muted_style),
    ]))
    .style(panel_style)
    .block(
        Block::default()
            .style(panel_style)
            .borders(Borders::TOP)
            .border_style(border_style),
    );

    frame.render_widget(message_panel, left_chunks[1]);
    frame.render_widget(input_panel, left_chunks[2]);
    frame.render_stateful_widget(sidebar, body_chunks[1], &mut list_state);
    frame.render_widget(footer, chunks[1]);

    if input_inner.width > 0 && input_inner.height > 0 {
        let cursor_chars = input_chars.saturating_sub(start_char);
        let cursor_offset = u16::try_from(cursor_chars).unwrap_or(u16::MAX);
        let cursor_x = input_inner
            .x
            .saturating_add(cursor_offset.min(input_inner.width.saturating_sub(1)));
        frame.set_cursor_position((cursor_x, input_inner.y));
    }
}

fn spawn_tui_inbound_task(
    mut inbound: tonic::Streaming<ServerMessage>,
    tx: mpsc::UnboundedSender<TuiInboundEvent>,
) {
    tokio::spawn(async move {
        while let Some(message) = inbound.message().await.transpose() {
            match message {
                Ok(server_message) => {
                    if tx.send(TuiInboundEvent::Message(server_message)).is_err() {
                        return;
                    }
                }
                Err(status) => {
                    let _ = tx.send(TuiInboundEvent::StreamError(status.to_string()));
                    return;
                }
            }
        }
        let _ = tx.send(TuiInboundEvent::StreamClosed);
    });
}

impl TuiAppState {
    async fn handle_tui_key_exchange_message(
        &mut self,
        message: newspeak::KeyExchangeMessage,
        key_info: &Arc<Mutex<KeyExchangeUser>>,
        storage: &LocalStorage,
        username: &str,
    ) -> Result<()> {
        let timestamp = super::timestamp_seconds(message.timestamp.as_ref());
        let Some(init_message) = message.initial_message.as_ref() else {
            self.set_status("missing initial message in key exchange");
            return Ok(());
        };

        let init = match PQXDHInitMessage::try_from(init_message) {
            Ok(init) => init,
            Err(err) => {
                self.set_status(format!("failed to parse key exchange: {}", err));
                return Ok(());
            }
        };

        let (
            shared_key,
            sending_sk,
            one_time_prekey_used,
            kem_used,
            last_resort_id,
            local_identity,
        ) = {
            let mut key_info = key_info.lock().await;
            let shared_key = match key_info.receive_key_exchange(&init) {
                Ok(shared_key) => shared_key,
                Err(err) => {
                    self.set_status(format!("failed to receive key exchange: {}", err));
                    return Ok(());
                }
            };
            let one_time_prekey_used = init.one_time_prekey_used;
            if let Some(id) = one_time_prekey_used {
                key_info.one_time_keys.mark_used(&id);
            }
            let kem_used = init.kem_used;
            if kem_used != key_info.last_resort_id {
                key_info.one_time_kem_keys.mark_used(&kem_used);
            }
            (
                shared_key,
                key_info.signed_prekey.private_key.clone(),
                one_time_prekey_used,
                kem_used,
                key_info.last_resort_id,
                key_info.identity_pk.to_bytes(),
            )
        };

        let peer_identity = init.peer_identity_public_key.to_bytes();
        let store_result = storage
            .store_peer_identity(username, &message.sender_id, &peer_identity)
            .await?;
        if matches!(store_result, PeerIdentityStoreResult::ExistingMismatch) {
            self.set_status(format!(
                "identity key mismatch for {}; refusing key exchange",
                message.sender_id
            ));
            return Ok(());
        }
        let show_safety = match store_result {
            PeerIdentityStoreResult::Inserted => true,
            PeerIdentityStoreResult::ExistingMatch { verified } => !verified,
            PeerIdentityStoreResult::ExistingMismatch => false,
        };
        if show_safety {
            let safety_number = verification::safety_number_string(&local_identity, &peer_identity);
            if self.active_peer.as_deref() == Some(message.sender_id.as_str()) {
                self.safety_number = Some(safety_number.clone());
                self.push_system_line(
                    timestamp,
                    format!(
                        "safety number with {}: {}",
                        message.sender_id, safety_number
                    ),
                );
            }
        }

        if let Some(id) = one_time_prekey_used
            && let Err(err) = storage.mark_ec_key_used(username, id).await
        {
            self.set_status(format!("failed to mark one-time prekey used: {}", err));
        }

        if kem_used != last_resort_id
            && let Err(err) = storage.mark_kem_key_used(username, &kem_used).await
        {
            self.set_status(format!("failed to mark one-time kem key used: {}", err));
        }

        let mut ratchet = RatchetState::as_receiver(shared_key);
        ratchet.sending_sk = sending_sk;
        ratchet.sending_pk = x25519::PublicKey::from(&ratchet.sending_sk);
        storage
            .update_conversation(username, &message.sender_id, &ratchet)
            .await?;

        self.ensure_conversation(&message.sender_id);
        if self.active_peer.as_deref() == Some(message.sender_id.as_str()) {
            self.active_ratchet = Some(ratchet);
            self.push_system_line(
                timestamp,
                format!("key exchange completed with {}", message.sender_id),
            );
        } else {
            self.set_status(format!("key exchange completed with {}", message.sender_id));
        }

        Ok(())
    }

    async fn handle_tui_encrypted_message(
        &mut self,
        message: newspeak::EncryptedMessage,
        storage: &LocalStorage,
        username: &str,
    ) -> Result<()> {
        let timestamp = super::timestamp_seconds(message.timestamp.as_ref());
        let sender_id = message.sender_id.clone();
        let aad = super::ratchet_aad(message.sender_id.as_str(), message.receiver_id.as_str());
        let Some(inner) = message.ratchet_message else {
            self.set_status("missing ratchet message");
            return Ok(());
        };
        let ratchet_message = match RatchetMessage::try_from(inner) {
            Ok(msg) => msg,
            Err(err) => {
                self.set_status(format!("invalid ratchet message: {}", err));
                return Ok(());
            }
        };

        let is_current = self.active_peer.as_deref() == Some(sender_id.as_str());
        if is_current {
            if self.active_ratchet.is_none() {
                self.active_ratchet = storage.get_conversation(username, &sender_id).await?;
            }
            let Some(ratchet) = self.active_ratchet.as_mut() else {
                self.set_status("received message before key exchange");
                return Ok(());
            };
            match ratchet.receive_message(ratchet_message, &aad) {
                Ok(plaintext) => {
                    storage
                        .add_message(username, &sender_id, &plaintext, false, timestamp)
                        .await?;
                    storage
                        .update_conversation(username, &sender_id, ratchet)
                        .await?;
                    self.push_line(timestamp, sender_id, plaintext, TuiLineKind::Incoming);
                }
                Err(err) => {
                    self.set_status(format!("failed to receive message: {}", err));
                }
            }
            return Ok(());
        }

        let Some(mut ratchet) = storage.get_conversation(username, &sender_id).await? else {
            self.set_status(format!(
                "received message before key exchange from {}",
                sender_id
            ));
            return Ok(());
        };
        match ratchet.receive_message(ratchet_message, &aad) {
            Ok(plaintext) => {
                storage
                    .add_message(username, &sender_id, &plaintext, false, timestamp)
                    .await?;
                storage
                    .update_conversation(username, &sender_id, &ratchet)
                    .await?;
                *self.unread_counts.entry(sender_id.clone()).or_insert(0) += 1;
                self.ensure_conversation(&sender_id);
                self.set_status(format!("new message from {}", sender_id));
            }
            Err(err) => {
                self.set_status(format!("failed to receive message: {}", err));
            }
        }

        Ok(())
    }

    async fn handle_tui_join_response(
        &mut self,
        join: JoinResponse,
        key_info: &Arc<Mutex<KeyExchangeUser>>,
        storage: &LocalStorage,
        username: &str,
        tx: &mpsc::Sender<ClientMessage>,
    ) -> Result<()> {
        let timestamp = super::timestamp_seconds(join.timestamp.as_ref());
        self.joined = true;
        self.set_status(join.message.clone());
        self.push_system_line(timestamp, format!("server: {}", join.message));

        let mut latest_timestamp: Option<Timestamp> = None;
        for offline in join.offline_messages {
            if let Some(timestamp) = offline.timestamp.as_ref() {
                let update = latest_timestamp.as_ref().map_or(true, |current| {
                    super::is_newer_timestamp(timestamp, current)
                });
                if update {
                    latest_timestamp = Some(timestamp.clone());
                }
            }

            let Some(message) = offline.message else {
                continue;
            };
            let Some(server_message) = super::server_message_from_client_message(message) else {
                continue;
            };
            match server_message.message_type {
                Some(server_message::MessageType::KeyExchange(message)) => {
                    self.handle_tui_key_exchange_message(message, key_info, storage, username)
                        .await?;
                }
                Some(server_message::MessageType::Encrypted(message)) => {
                    self.handle_tui_encrypted_message(message, storage, username)
                        .await?;
                }
                _ => {}
            }
        }

        if let Some(latest) = latest_timestamp {
            tx.send(ClientMessage {
                message_type: Some(client_message::MessageType::AckOfflineMessages(
                    AckOfflineMessages {
                        latest_timestamp: Some(latest),
                    },
                )),
            })
            .await?;
        }

        Ok(())
    }

    async fn process_tui_server_event(
        &mut self,
        event: TuiInboundEvent,
        key_info: &Arc<Mutex<KeyExchangeUser>>,
        storage: &LocalStorage,
        username: &str,
        tx: &mpsc::Sender<ClientMessage>,
    ) -> Result<()> {
        match event {
            TuiInboundEvent::Message(server_message) => match server_message.message_type {
                Some(server_message::MessageType::JoinResponse(join)) => {
                    self.handle_tui_join_response(join, key_info, storage, username, tx)
                        .await?;
                }
                Some(server_message::MessageType::KeyExchange(message)) => {
                    self.handle_tui_key_exchange_message(message, key_info, storage, username)
                        .await?;
                }
                Some(server_message::MessageType::Encrypted(message)) => {
                    self.handle_tui_encrypted_message(message, storage, username)
                        .await?;
                }
                None => {
                    self.set_status("server sent an empty message");
                }
            },
            TuiInboundEvent::StreamError(err) => {
                self.set_status(format!("stream error: {}", err));
            }
            TuiInboundEvent::StreamClosed => {
                self.set_status("stream closed by server");
            }
        }
        Ok(())
    }

    async fn initiate_tui_key_exchange_if_needed(
        &mut self,
        user: &mut User<'_>,
        username: &str,
        receiver: &str,
        storage: &LocalStorage,
        tx: &mpsc::Sender<ClientMessage>,
    ) -> Result<()> {
        if self.active_ratchet.is_some() {
            return Ok(());
        }

        let (key_message, r_state, peer_identity) = user
            .create_key_exchange_message(receiver.to_string())
            .await?;
        let store_result = storage
            .store_peer_identity(username, receiver, &peer_identity)
            .await?;
        if matches!(store_result, PeerIdentityStoreResult::ExistingMismatch) {
            return Err(anyhow!(
                "identity key mismatch for {}; refusing to start conversation",
                receiver
            ));
        }

        let show_safety = match store_result {
            PeerIdentityStoreResult::Inserted => true,
            PeerIdentityStoreResult::ExistingMatch { verified } => !verified,
            PeerIdentityStoreResult::ExistingMismatch => false,
        };
        if show_safety {
            let safety_number = verification::safety_number_string(&self.local_identity, &peer_identity);
            self.safety_number = Some(safety_number.clone());
            self.push_system_line(
                super::now_unix_seconds(),
                format!("safety number with {}: {}", receiver, safety_number),
            );
        }

        storage
            .update_conversation(username, receiver, &r_state)
            .await?;
        self.active_ratchet = Some(r_state);
        self.ensure_conversation(receiver);

        tx.send(ClientMessage {
            message_type: Some(client_message::MessageType::KeyExchangeMessage(key_message)),
        })
        .await?;

        self.push_system_line(
            super::now_unix_seconds(),
            format!("key exchange initiated with {}", receiver),
        );
        Ok(())
    }

    async fn send_tui_chat_message(
        &mut self,
        line: &str,
        username: &str,
        storage: &LocalStorage,
        tx: &mpsc::Sender<ClientMessage>,
    ) -> Result<()> {
        if !self.joined {
            self.set_status("still joining server stream...");
            return Ok(());
        }

        let Some(receiver) = self.active_peer.clone() else {
            self.set_status("no active conversation; use /init <username> or pick from sidebar");
            return Ok(());
        };

        if self.active_ratchet.is_none() {
            self.active_ratchet = storage.get_conversation(username, &receiver).await?;
        }
        let Some(state) = self.active_ratchet.as_mut() else {
            self.set_status("no ratchet state for this conversation; run /init <username>");
            return Ok(());
        };

        let timestamp = super::now_unix_seconds();
        let message_timestamp = Timestamp {
            seconds: timestamp,
            nanos: 0,
        };
        let aad = super::ratchet_aad(username, &receiver);
        let msg = match state.send_message(line, &aad) {
            Ok(msg) => msg,
            Err(err) => {
                self.set_status(format!("failed to construct message: {}", err));
                return Ok(());
            }
        };

        let rpc_message = EncryptedMessage {
            sender_id: username.to_string(),
            receiver_id: receiver.clone(),
            ratchet_message: Some(msg.into()),
            timestamp: Some(message_timestamp),
        };

        storage
            .add_message(username, &receiver, line, true, timestamp)
            .await?;
        storage
            .update_conversation(username, &receiver, state)
            .await?;

        tx.send(ClientMessage {
            message_type: Some(client_message::MessageType::EncryptedMessage(rpc_message)),
        })
        .await?;

        self.push_line(
            timestamp,
            username.to_string(),
            line.to_string(),
            TuiLineKind::Outgoing,
        );
        self.set_status(format!("sent message to {}", receiver));
        Ok(())
    }

    async fn submit_tui_input(
        &mut self,
        user: &mut User<'_>,
        storage: &LocalStorage,
        tx: &mpsc::Sender<ClientMessage>,
        username: &str,
    ) -> Result<()> {
        let raw_input = std::mem::take(&mut self.input);
        let trimmed = raw_input.trim();

        if trimmed.is_empty() {
            if let Some(peer) = self.selected_peer() {
                self.activate_tui_conversation(storage, username, &peer)
                    .await?;
            }
            return Ok(());
        }

        if trimmed == "/quit" || trimmed == "exit" {
            self.should_quit = true;
            return Ok(());
        }

        if trimmed == "/help" {
            self.push_system_line(
                super::now_unix_seconds(),
                "commands: /init <user>, /switch <user>, /verify, /quit",
            );
            return Ok(());
        }

        let mut parts = trimmed.split_whitespace();
        if parts.next() == Some("/init") {
            let Some(receiver) = parts.next() else {
                self.set_status("usage: /init <username>");
                return Ok(());
            };
            if receiver == username {
                self.set_status("cannot start a conversation with yourself");
                return Ok(());
            }
            self.activate_tui_conversation(storage, username, receiver)
                .await?;
            if let Err(err) = self
                .initiate_tui_key_exchange_if_needed(user, username, receiver, storage, tx)
                .await
            {
                self.set_status(format!("init failed: {}", err));
            }
            return Ok(());
        }

        let mut parts = trimmed.split_whitespace();
        if parts.next() == Some("/switch") {
            let target = if let Some(peer) = parts.next() {
                peer.to_string()
            } else if let Some(peer) = self.selected_peer() {
                peer
            } else {
                self.set_status("usage: /switch <username>");
                return Ok(());
            };

            self.activate_tui_conversation(storage, username, &target)
                .await?;
            return Ok(());
        }

        if trimmed == "/verify" {
            let Some(receiver) = self.active_peer.clone() else {
                self.set_status("no active conversation; use /init <username> first");
                return Ok(());
            };
            match storage
                .mark_peer_identity_verified(username, &receiver)
                .await
            {
                Ok(true) => {
                    self.safety_number = None;
                    self.push_system_line(
                        super::now_unix_seconds(),
                        format!("marked {} as verified", receiver),
                    );
                }
                Ok(false) => {
                    self.set_status("no identity on record for this peer");
                }
                Err(err) => {
                    self.set_status(format!("verification failed: {}", err));
                }
            }
            return Ok(());
        }

        if trimmed.starts_with('/') {
            self.set_status("unknown command; use /help");
            return Ok(());
        }

        self.send_tui_chat_message(raw_input.trim_end(), username, storage, tx)
            .await
    }

    async fn handle_tui_key_event(
        &mut self,
        key: event::KeyEvent,
        user: &mut User<'_>,
        storage: &LocalStorage,
        tx: &mpsc::Sender<ClientMessage>,
        username: &str,
    ) -> Result<()> {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Up => self.move_selection_up(),
            KeyCode::Down => self.move_selection_down(),
            KeyCode::Tab => {
                if let Some(peer) = self.selected_peer() {
                    self.activate_tui_conversation(storage, username, &peer)
                        .await?;
                }
            }
            KeyCode::Enter => {
                self.submit_tui_input(user, storage, tx, username).await?;
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Esc => {
                if self.input.is_empty() {
                    self.should_quit = true;
                } else {
                    self.input.clear();
                    self.set_status("input cleared");
                }
            }
            KeyCode::Char(ch)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.input.push(ch);
            }
            _ => {}
        }

        Ok(())
    }
}

pub async fn run(username: String, receiver_arg: Option<String>) -> Result<()> {
    let client = NewspeakClient::connect("http://[::1]:10000").await?;
    let storage = LocalStorage::new(&username).await?;
    let key_info = storage.load_or_create_user(&username).await?;
    let mut user = User::new(&username, client, key_info);
    user.register().await?;

    let (tx, inbound) = user.setup_message_stream().await?;
    user.send_join_request(&tx).await?;

    let initial_receiver = receiver_arg.filter(|receiver| !receiver.trim().is_empty());
    let local_identity = {
        let key_info = user.key_info.lock().await;
        key_info.identity_pk.to_bytes()
    };
    let mut app = TuiAppState::new(username.clone(), initial_receiver.clone(), local_identity);
    if let Some(receiver) = initial_receiver.as_deref() {
        app.activate_tui_conversation(&storage, &username, receiver)
            .await?;
    }
    app.refresh_tui_conversations(&storage, &username).await?;

    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
    spawn_tui_inbound_task(inbound, inbound_tx);

    let mut pending_initial_init = initial_receiver.clone();
    let mut terminal = ratatui::init();
    let run_result = async {
        loop {
            while let Ok(event) = inbound_rx.try_recv() {
                if let Err(err) = app
                    .process_tui_server_event(event, &user.key_info, &storage, &username, &tx)
                    .await
                {
                    app.set_status(format!("server handling failed: {}", err));
                }
            }

            if app.joined
                && let Some(receiver) = pending_initial_init.take()
                && let Err(err) = app
                    .initiate_tui_key_exchange_if_needed(
                        &mut user, &username, &receiver, &storage, &tx,
                    )
                    .await
            {
                app.set_status(format!("init failed: {}", err));
            }

            if let Err(err) = app.refresh_tui_conversations(&storage, &username).await {
                app.set_status(format!("failed to refresh conversations: {}", err));
            }

            terminal.draw(|frame| render_ratatui_chat(frame, &app))?;
            if app.should_quit {
                break Ok(());
            }

            if event::poll(Duration::from_millis(40))?
                && let Event::Key(key) = event::read()?
                && let Err(err) = app
                    .handle_tui_key_event(key, &mut user, &storage, &tx, &username)
                    .await
            {
                app.set_status(format!("input handling failed: {}", err));
            }
        }
    }
    .await;

    ratatui::restore();
    run_result
}
