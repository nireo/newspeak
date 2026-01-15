use super::*;

#[test]
fn safety_number_is_order_independent() {
    let a: [u8; 32] = rand::random();
    let b: [u8; 32] = rand::random();

    let left = safety_number_string(&a, &b);
    let right = safety_number_string(&b, &a);

    assert_eq!(left, right);
}

#[test]
fn safety_number_format_is_numeric_groups() {
    let a = [1u8; 32];
    let b = [2u8; 32];

    let safety = safety_number_string(&a, &b);
    let groups: Vec<&str> = safety.split_whitespace().collect();

    assert_eq!(groups.len(), SAFETY_NUMBER_GROUPS);
    assert!(groups.iter().all(|group| group.len() == 5));
    assert!(safety
        .chars()
        .all(|ch| ch.is_ascii_digit() || ch == ' '));
}
