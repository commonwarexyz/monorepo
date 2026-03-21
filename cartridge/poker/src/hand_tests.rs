//! exhaustive hand evaluation correctness tests.
//!
//! verifies every hand category, tiebreakers, kickers, and edge cases.
//! card encoding: index 0..51, rank = index % 13 (0=2..12=A), suit = index / 13 (0=s,1=h,2=d,3=c)
//!
//! helper: card(rank, suit) where rank='2'..'A', suit='s','h','d','c'

#[cfg(test)]
mod hand_eval_tests {
    use crate::eval_5;

    fn c(rank: char, suit: char) -> u8 {
        let r = match rank {
            '2' => 0, '3' => 1, '4' => 2, '5' => 3, '6' => 4, '7' => 5,
            '8' => 6, '9' => 7, 'T' => 8, 'J' => 9, 'Q' => 10, 'K' => 11, 'A' => 12,
            _ => panic!("bad rank"),
        };
        let s = match suit {
            's' => 0, 'h' => 1, 'd' => 2, 'c' => 3,
            _ => panic!("bad suit"),
        };
        r + s * 13
    }

    fn hand(cards: [(char, char); 5]) -> [u8; 5] {
        [c(cards[0].0, cards[0].1), c(cards[1].0, cards[1].1), c(cards[2].0, cards[2].1),
         c(cards[3].0, cards[3].1), c(cards[4].0, cards[4].1)]
    }

    // ── category ordering ──────────────────────────────────

    #[test]
    fn test_category_ordering() {
        let high_card   = eval_5(hand([('7','s'), ('5','h'), ('3','d'), ('2','c'), ('9','s')]));
        let pair        = eval_5(hand([('7','s'), ('7','h'), ('3','d'), ('2','c'), ('9','s')]));
        let two_pair    = eval_5(hand([('7','s'), ('7','h'), ('3','d'), ('3','c'), ('9','s')]));
        let trips       = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('2','c'), ('9','s')]));
        let straight    = eval_5(hand([('5','s'), ('6','h'), ('7','d'), ('8','c'), ('9','s')]));
        let flush       = eval_5(hand([('2','s'), ('5','s'), ('7','s'), ('9','s'), ('J','s')]));
        let full_house  = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('3','c'), ('3','s')]));
        let quads       = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('7','c'), ('9','s')]));
        let str_flush   = eval_5(hand([('5','s'), ('6','s'), ('7','s'), ('8','s'), ('9','s')]));

        assert!(pair > high_card, "pair > high card");
        assert!(two_pair > pair, "two pair > pair");
        assert!(trips > two_pair, "trips > two pair");
        assert!(straight > trips, "straight > trips");
        assert!(flush > straight, "flush > straight");
        assert!(full_house > flush, "full house > flush");
        assert!(quads > full_house, "quads > full house");
        assert!(str_flush > quads, "straight flush > quads");
    }

    // ── straight flush ─────────────────────────────────────

    #[test]
    fn test_royal_flush_beats_lower_straight_flush() {
        let royal = eval_5(hand([('T','s'), ('J','s'), ('Q','s'), ('K','s'), ('A','s')]));
        let sf_9  = eval_5(hand([('5','s'), ('6','s'), ('7','s'), ('8','s'), ('9','s')]));
        assert!(royal > sf_9);
    }

    #[test]
    fn test_wheel_flush_is_lowest_straight_flush() {
        let wheel_flush = eval_5(hand([('A','s'), ('2','s'), ('3','s'), ('4','s'), ('5','s')]));
        let sf_6 = eval_5(hand([('2','h'), ('3','h'), ('4','h'), ('5','h'), ('6','h')]));
        assert!(sf_6 > wheel_flush, "6-high SF > wheel SF");

        // wheel SF still beats quads
        let quads = eval_5(hand([('A','s'), ('A','h'), ('A','d'), ('A','c'), ('K','s')]));
        assert!(wheel_flush > quads, "wheel SF > quads");
    }

    // ── quads ──────────────────────────────────────────────

    #[test]
    fn test_quads_higher_rank_wins() {
        let quad_a = eval_5(hand([('A','s'), ('A','h'), ('A','d'), ('A','c'), ('2','s')]));
        let quad_k = eval_5(hand([('K','s'), ('K','h'), ('K','d'), ('K','c'), ('A','s')]));
        assert!(quad_a > quad_k);
    }

    #[test]
    fn test_quads_same_rank_kicker() {
        let quad_7_a = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('7','c'), ('A','s')]));
        let quad_7_k = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('7','c'), ('K','s')]));
        assert!(quad_7_a > quad_7_k, "quads with A kicker > K kicker");
    }

    // ── full house ─────────────────────────────────────────

    #[test]
    fn test_full_house_trips_rank_matters() {
        let fh_a3 = eval_5(hand([('A','s'), ('A','h'), ('A','d'), ('3','c'), ('3','s')]));
        let fh_k3 = eval_5(hand([('K','s'), ('K','h'), ('K','d'), ('3','c'), ('3','h')]));
        assert!(fh_a3 > fh_k3, "AAA33 > KKK33");
    }

    #[test]
    fn test_full_house_pair_rank_breaks_tie() {
        let fh_7k = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('K','c'), ('K','s')]));
        let fh_7q = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('Q','c'), ('Q','s')]));
        assert!(fh_7k > fh_7q, "777KK > 777QQ");
    }

    // ── flush ──────────────────────────────────────────────

    #[test]
    fn test_flush_high_card_wins() {
        let flush_a = eval_5(hand([('A','s'), ('9','s'), ('7','s'), ('5','s'), ('3','s')]));
        let flush_k = eval_5(hand([('K','s'), ('9','s'), ('7','s'), ('5','s'), ('3','s')]));
        assert!(flush_a > flush_k, "A-high flush > K-high flush");
    }

    #[test]
    fn test_flush_second_card_breaks_tie() {
        let flush_aq = eval_5(hand([('A','s'), ('Q','s'), ('7','s'), ('5','s'), ('3','s')]));
        let flush_aj = eval_5(hand([('A','s'), ('J','s'), ('7','s'), ('5','s'), ('3','s')]));
        assert!(flush_aq > flush_aj, "AQ flush > AJ flush");
    }

    // ── straight ───────────────────────────────────────────

    #[test]
    fn test_straight_higher_top_wins() {
        let str_t = eval_5(hand([('6','s'), ('7','h'), ('8','d'), ('9','c'), ('T','s')]));
        let str_9 = eval_5(hand([('5','s'), ('6','h'), ('7','d'), ('8','c'), ('9','s')]));
        assert!(str_t > str_9, "T-high straight > 9-high straight");
    }

    #[test]
    fn test_broadway_straight() {
        let broadway = eval_5(hand([('T','s'), ('J','h'), ('Q','d'), ('K','c'), ('A','s')]));
        let str_k = eval_5(hand([('9','s'), ('T','h'), ('J','d'), ('Q','c'), ('K','s')]));
        assert!(broadway > str_k, "broadway > K-high straight");
    }

    #[test]
    fn test_wheel_is_lowest_straight() {
        let wheel = eval_5(hand([('A','s'), ('2','h'), ('3','d'), ('4','c'), ('5','s')]));
        let str_6 = eval_5(hand([('2','s'), ('3','h'), ('4','d'), ('5','c'), ('6','s')]));
        assert!(str_6 > wheel, "6-high straight > wheel");

        // wheel still beats trips
        let trips = eval_5(hand([('A','s'), ('A','h'), ('A','d'), ('K','c'), ('Q','s')]));
        assert!(wheel > trips, "wheel > trips");
    }

    // ── trips ──────────────────────────────────────────────

    #[test]
    fn test_trips_rank_matters() {
        let trips_a = eval_5(hand([('A','s'), ('A','h'), ('A','d'), ('5','c'), ('3','s')]));
        let trips_k = eval_5(hand([('K','s'), ('K','h'), ('K','d'), ('Q','c'), ('J','s')]));
        assert!(trips_a > trips_k, "trip aces > trip kings");
    }

    #[test]
    fn test_trips_kicker_breaks_tie() {
        let trips_7ka = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('A','c'), ('K','s')]));
        let trips_7kq = eval_5(hand([('7','s'), ('7','h'), ('7','d'), ('K','c'), ('Q','s')]));
        assert!(trips_7ka > trips_7kq, "777AK > 777KQ");
    }

    // ── two pair ───────────────────────────────────────────

    #[test]
    fn test_two_pair_high_pair_wins() {
        let aa33 = eval_5(hand([('A','s'), ('A','h'), ('3','d'), ('3','c'), ('5','s')]));
        let kk33 = eval_5(hand([('K','s'), ('K','h'), ('3','d'), ('3','c'), ('5','s')]));
        assert!(aa33 > kk33, "AA33 > KK33");
    }

    #[test]
    fn test_two_pair_low_pair_breaks_tie() {
        let aakk = eval_5(hand([('A','s'), ('A','h'), ('K','d'), ('K','c'), ('5','s')]));
        let aaqq = eval_5(hand([('A','s'), ('A','h'), ('Q','d'), ('Q','c'), ('5','s')]));
        assert!(aakk > aaqq, "AAKK > AAQQ");
    }

    #[test]
    fn test_two_pair_kicker_breaks_tie() {
        let aakk_q = eval_5(hand([('A','s'), ('A','h'), ('K','d'), ('K','c'), ('Q','s')]));
        let aakk_j = eval_5(hand([('A','s'), ('A','h'), ('K','d'), ('K','c'), ('J','s')]));
        assert!(aakk_q > aakk_j, "AAKKQ > AAKKJ");
    }

    // ── pair ───────────────────────────────────────────────

    #[test]
    fn test_pair_rank_matters() {
        let pair_a = eval_5(hand([('A','s'), ('A','h'), ('5','d'), ('3','c'), ('2','s')]));
        let pair_k = eval_5(hand([('K','s'), ('K','h'), ('Q','d'), ('J','c'), ('T','s')]));
        assert!(pair_a > pair_k, "pair of aces > pair of kings");
    }

    #[test]
    fn test_pair_kicker_chain() {
        let aa_kqj = eval_5(hand([('A','s'), ('A','h'), ('K','d'), ('Q','c'), ('J','s')]));
        let aa_kqt = eval_5(hand([('A','s'), ('A','h'), ('K','d'), ('Q','c'), ('T','s')]));
        let aa_kj9 = eval_5(hand([('A','s'), ('A','h'), ('K','d'), ('J','c'), ('9','s')]));
        assert!(aa_kqj > aa_kqt, "AAKQJ > AAKQT");
        assert!(aa_kqt > aa_kj9, "AAKQT > AAKJ9");
    }

    // ── high card ──────────────────────────────────────────

    #[test]
    fn test_high_card_ranking() {
        let akqjt = eval_5(hand([('A','s'), ('K','h'), ('Q','d'), ('J','c'), ('9','s')]));
        let akqj8 = eval_5(hand([('A','s'), ('K','h'), ('Q','d'), ('J','c'), ('8','s')]));
        assert!(akqjt > akqj8, "AKQJTish > AKQJ8");
    }

    #[test]
    fn test_high_card_fifth_card() {
        let a5432 = eval_5(hand([('A','s'), ('5','h'), ('4','d'), ('3','c'), ('2','s')]));
        let k_high = eval_5(hand([('K','s'), ('Q','h'), ('J','d'), ('T','c'), ('8','s')]));
        assert!(a5432 > k_high, "A-high > K-high (even with bad kickers)");
    }

    // ── exact ties ─────────────────────────────────────────

    #[test]
    fn test_identical_hands_tie() {
        let h1 = eval_5(hand([('A','s'), ('K','h'), ('Q','d'), ('J','c'), ('9','s')]));
        let h2 = eval_5(hand([('A','h'), ('K','d'), ('Q','c'), ('J','s'), ('9','h')]));
        assert_eq!(h1, h2, "same ranks different suits = tie");
    }

    #[test]
    fn test_flush_tie_same_ranks() {
        let f1 = eval_5(hand([('A','s'), ('K','s'), ('Q','s'), ('J','s'), ('9','s')]));
        let f2 = eval_5(hand([('A','h'), ('K','h'), ('Q','h'), ('J','h'), ('9','h')]));
        assert_eq!(f1, f2, "same-rank flushes in different suits = tie");
    }

    // ── 7-card best-hand selection ─────────────────────────

    #[test]
    fn test_best_hand_from_7() {
        use crate::{GameState, Rules};

        let mut state = GameState::new(Rules::default(), 2);
        // seat 0: A♠ K♠ — makes nut flush with community spades
        // seat 1: 2♥ 3♥ — nothing
        // community: 5♠ 7♠ 9♠ J♦ 4♣ — three spades for seat 0
        state.cards[0] = [c('A','s'), c('K','s')];
        state.cards[1] = [c('2','h'), c('3','h')];
        state.community = [c('5','s'), c('7','s'), c('9','s'), c('J','d'), c('4','c')];
        state.community_count = 5;

        let s0 = state.best_hand(0);
        let s1 = state.best_hand(1);
        assert!(s0 > s1, "AK suited with 3 spades on board = flush, beats 23o");
    }

    #[test]
    fn test_best_hand_uses_board() {
        use crate::{GameState, Rules};

        let mut state = GameState::new(Rules::default(), 2);
        // both have garbage, board has a straight
        // community: 5 6 7 8 9 (all different suits)
        state.cards[0] = [c('2','s'), c('3','h')];
        state.cards[1] = [c('2','d'), c('3','c')];
        state.community = [c('5','s'), c('6','h'), c('7','d'), c('8','c'), c('9','s')];
        state.community_count = 5;

        let s0 = state.best_hand(0);
        let s1 = state.best_hand(1);
        assert_eq!(s0, s1, "both use board straight = tie");
    }

    #[test]
    fn test_best_hand_pocket_pair_wins() {
        use crate::{GameState, Rules};

        let mut state = GameState::new(Rules::default(), 2);
        // seat 0: A♠ A♥ — pocket aces
        // seat 1: K♠ Q♠ — high cards
        // community: 2♦ 7♣ 9♠ J♥ 3♦ — no straight, no flush
        state.cards[0] = [c('A','s'), c('A','h')];
        state.cards[1] = [c('K','s'), c('Q','h')]; // different suits to avoid flush
        state.community = [c('2','d'), c('7','c'), c('9','s'), c('J','h'), c('3','d')];
        state.community_count = 5;

        let s0 = state.best_hand(0);
        let s1 = state.best_hand(1);
        assert!(s0 > s1, "pocket aces beat KQ high");
    }

    #[test]
    fn test_board_straight_splits() {
        use crate::{GameState, Rules};

        let mut state = GameState::new(Rules::default(), 2);
        // both have garbage, board has a straight: 2-3-4-5-6
        state.cards[0] = [c('A','s'), c('A','h')]; // AA makes wheel too, but 6-high board straight is better
        state.cards[1] = [c('K','s'), c('Q','h')]; // also uses 6-high board straight
        state.community = [c('2','d'), c('3','c'), c('4','s'), c('5','h'), c('6','d')];
        state.community_count = 5;

        let s0 = state.best_hand(0);
        let s1 = state.best_hand(1);
        assert_eq!(s0, s1, "both use 2-3-4-5-6 board straight = tie");
    }
}
