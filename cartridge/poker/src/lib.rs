//! Deterministic poker state machine.
//!
//! Pure function: (state, signed_action) -> (new_state, events).
//! No IO, no randomness, no heap allocation. Compiles to native,
//! WASM, or RISC-V (PolkaVM guest, provable via WIM).
//!
//! Supports 2-10 players with fixed-size arrays.

#![cfg_attr(not(any(feature = "std", test)), no_std)]


#[cfg(test)]
mod fuzz;

#[cfg(test)]
mod hand_tests;

// ============================================================================
// Constants
// ============================================================================

pub const MAX_SEATS: usize = 10;
pub const MAX_COMMUNITY: usize = 5;
pub const MAX_ACTIONS: usize = 128;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Negotiate = 0,
    Escrow = 1,
    Preflop = 2,
    Flop = 3,
    Turn = 4,
    River = 5,
    Showdown = 6,
    Settled = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Fold = 0,
    Check = 1,
    Call = 2,
    Bet = 3,
    Raise = 4,
    AllIn = 5,
}

impl Action {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v { 0 => Some(Self::Fold), 1 => Some(Self::Check), 2 => Some(Self::Call),
                   3 => Some(Self::Bet), 4 => Some(Self::Raise), 5 => Some(Self::AllIn), _ => None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SeatState {
    Empty = 0,
    Active = 1,
    SittingOut = 2,
    Folded = 3,
    AllIn = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct SignedAction {
    pub seat: u8,
    pub action: Action,
    pub amount: u32,
    pub seq: u32,
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, Copy)]
pub struct Rules {
    pub buyin: u32,
    pub small_blind: u32,
    pub big_blind: u32,
    pub turn_timeout_blocks: u32,
    /// rake percentage in basis points (100 = 1%). 0 = no rake.
    pub rake_bps: u16,
    /// max rake per pot (0 = unlimited)
    pub rake_cap: u32,
}

impl Default for Rules {
    fn default() -> Self {
        Self { buyin: 1000, small_blind: 5, big_blind: 10, turn_timeout_blocks: 6, rake_bps: 0, rake_cap: 0 }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ActionResult {
    pub valid: bool,
    pub hand_over: bool,
    pub winner: u8,      // 255 = no winner yet / split
    pub payout: u32,
    pub advance_phase: bool,
}

// ============================================================================
// Game state (fixed-size, N seats, no heap in pvm mode)
// ============================================================================

#[derive(Debug, Clone)]
pub struct GameState {
    pub phase: Phase,
    pub rules: Rules,
    pub num_players: u8,
    pub hand_number: u32,
    pub button: u8,
    pub stacks: [u32; MAX_SEATS],
    pub pot: u32,
    pub bets: [u32; MAX_SEATS],
    pub seat_state: [SeatState; MAX_SEATS],
    pub cards: [[u8; 2]; MAX_SEATS],
    pub community: [u8; MAX_COMMUNITY],
    pub community_count: u8,
    pub acting_seat: u8,
    pub round_actions: u8,
    pub last_aggressor: u8,
    pub action_count: u32,
    pub last_action_hash: [u8; 32],
    /// rake collected this hand
    pub rake: u32,
}

// ============================================================================
// Opponent profiling — tracks stats per seat across hands
// ============================================================================

/// player type classification based on observed stats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PlayerType {
    Unknown = 0,
    Rock = 1,         // VPIP < 20%, low aggression
    TAG = 2,          // VPIP 20-30%, high aggression
    LAG = 3,          // VPIP > 40%, high aggression
    CallingStation = 4, // VPIP > 40%, low aggression
    Maniac = 5,       // VPIP > 60%, very high aggression, high allin%
    Nit = 6,          // VPIP < 12%, folds almost everything
}

/// per-seat opponent stats, updated after every action
#[derive(Debug, Clone, Copy)]
pub struct PlayerProfile {
    // raw counters
    pub hands_seen: u32,
    pub vpip_count: u32,       // voluntarily put money in pot
    pub pfr_count: u32,        // preflop raise
    pub postflop_bets: u32,    // bets + raises postflop
    pub postflop_calls: u32,   // calls postflop
    pub postflop_checks: u32,  // checks postflop
    pub postflop_folds: u32,   // folds postflop
    pub allin_count: u32,      // all-in actions
    pub showdowns_seen: u32,   // went to showdown
    pub showdowns_won: u32,    // won at showdown
    pub three_bet_count: u32,  // 3-bet preflop
    pub cbet_count: u32,       // continuation bet (bet flop after pfr)
    pub cbet_opportunities: u32,

    // per-hand tracking (reset each hand)
    pub acted_preflop: bool,
    pub raised_preflop: bool,
    pub was_pfr: bool,         // was the preflop raiser (for cbet tracking)
}

impl Default for PlayerProfile {
    fn default() -> Self {
        Self {
            hands_seen: 0, vpip_count: 0, pfr_count: 0,
            postflop_bets: 0, postflop_calls: 0, postflop_checks: 0,
            postflop_folds: 0, allin_count: 0, showdowns_seen: 0,
            showdowns_won: 0, three_bet_count: 0,
            cbet_count: 0, cbet_opportunities: 0,
            acted_preflop: false, raised_preflop: false, was_pfr: false,
        }
    }
}

impl PlayerProfile {
    /// VPIP: voluntarily put money in pot (0.0 - 1.0)
    pub fn vpip(&self) -> f32 {
        if self.hands_seen == 0 { return 0.5; } // unknown = assume average
        self.vpip_count as f32 / self.hands_seen as f32
    }

    /// PFR: preflop raise frequency (0.0 - 1.0)
    pub fn pfr(&self) -> f32 {
        if self.hands_seen == 0 { return 0.2; }
        self.pfr_count as f32 / self.hands_seen as f32
    }

    /// aggression factor: (bets + raises) / calls. higher = more aggressive
    pub fn aggression_factor(&self) -> f32 {
        let aggressive = self.postflop_bets as f32;
        let passive = self.postflop_calls.max(1) as f32;
        aggressive / passive
    }

    /// went to showdown frequency
    pub fn wtsd(&self) -> f32 {
        if self.hands_seen == 0 { return 0.3; }
        self.showdowns_seen as f32 / self.hands_seen as f32
    }

    /// won at showdown frequency
    pub fn w_sd(&self) -> f32 {
        if self.showdowns_seen == 0 { return 0.5; }
        self.showdowns_won as f32 / self.showdowns_seen as f32
    }

    /// all-in frequency
    pub fn allin_pct(&self) -> f32 {
        if self.hands_seen == 0 { return 0.05; }
        self.allin_count as f32 / self.hands_seen as f32
    }

    /// continuation bet frequency
    pub fn cbet(&self) -> f32 {
        if self.cbet_opportunities == 0 { return 0.5; }
        self.cbet_count as f32 / self.cbet_opportunities as f32
    }

    /// confidence weight: 1% at 0 hands → 15% cap at 100+ hands
    pub fn confidence_weight(&self) -> f32 {
        (0.01 + 0.14 * (self.hands_seen as f32 / 100.0)).min(0.15)
    }

    /// classify player type from observed stats
    pub fn classify(&self) -> PlayerType {
        if self.hands_seen < 10 { return PlayerType::Unknown; }

        let vpip = self.vpip();
        let _pfr = self.pfr();
        let af = self.aggression_factor();
        let allin = self.allin_pct();

        // maniac: shoves constantly
        if allin > 0.3 || (vpip > 0.6 && af > 4.0) {
            return PlayerType::Maniac;
        }
        // nit: barely plays
        if vpip < 0.12 {
            return PlayerType::Nit;
        }
        // rock: tight passive
        if vpip < 0.20 && af < 2.0 {
            return PlayerType::Rock;
        }
        // TAG: tight aggressive
        if vpip < 0.30 && af >= 2.0 {
            return PlayerType::TAG;
        }
        // calling station: loose passive
        if vpip >= 0.40 && af < 1.5 {
            return PlayerType::CallingStation;
        }
        // LAG: loose aggressive
        if vpip >= 0.35 && af >= 2.0 {
            return PlayerType::LAG;
        }

        PlayerType::Unknown
    }

    /// encode as feature vector for neural net input (16 floats)
    pub fn to_features(&self) -> [f32; 16] {
        [
            self.vpip(),
            self.pfr(),
            self.aggression_factor().min(10.0) / 10.0, // normalize
            self.wtsd(),
            self.w_sd(),
            self.allin_pct(),
            self.cbet(),
            (self.hands_seen as f32).min(200.0) / 200.0, // confidence
            // one-hot player type
            if self.classify() == PlayerType::Rock { 1.0 } else { 0.0 },
            if self.classify() == PlayerType::TAG { 1.0 } else { 0.0 },
            if self.classify() == PlayerType::LAG { 1.0 } else { 0.0 },
            if self.classify() == PlayerType::CallingStation { 1.0 } else { 0.0 },
            if self.classify() == PlayerType::Maniac { 1.0 } else { 0.0 },
            if self.classify() == PlayerType::Nit { 1.0 } else { 0.0 },
            // gap between VPIP and PFR (higher = more passive preflop)
            (self.vpip() - self.pfr()).max(0.0),
            // 3-bet frequency
            if self.hands_seen > 0 { self.three_bet_count as f32 / self.hands_seen as f32 } else { 0.1 },
        ]
    }

    /// call after each new hand is dealt
    pub fn new_hand(&mut self) {
        self.hands_seen += 1;
        self.acted_preflop = false;
        self.raised_preflop = false;
        self.was_pfr = false;
    }

    /// call after each action is observed
    pub fn observe_action(&mut self, action: Action, phase: Phase, is_facing_raise: bool) {
        match phase {
            Phase::Preflop => {
                if !self.acted_preflop {
                    self.acted_preflop = true;
                    match action {
                        Action::Call | Action::Bet | Action::Raise | Action::AllIn => {
                            self.vpip_count += 1;
                        }
                        _ => {}
                    }
                }
                match action {
                    Action::Bet | Action::Raise => {
                        self.pfr_count += 1;
                        self.raised_preflop = true;
                        self.was_pfr = true;
                        if is_facing_raise {
                            self.three_bet_count += 1;
                        }
                    }
                    Action::AllIn => {
                        self.pfr_count += 1;
                        self.allin_count += 1;
                        self.was_pfr = true;
                    }
                    _ => {}
                }
            }
            Phase::Flop | Phase::Turn | Phase::River => {
                match action {
                    Action::Bet | Action::Raise => {
                        self.postflop_bets += 1;
                        // track cbet (first bet on flop by preflop raiser)
                        if phase == Phase::Flop && self.was_pfr {
                            self.cbet_count += 1;
                        }
                    }
                    Action::Call => { self.postflop_calls += 1; }
                    Action::Check => {
                        self.postflop_checks += 1;
                        // missed cbet
                        if phase == Phase::Flop && self.was_pfr {
                            self.cbet_opportunities += 1;
                        }
                    }
                    Action::Fold => { self.postflop_folds += 1; }
                    Action::AllIn => {
                        self.postflop_bets += 1;
                        self.allin_count += 1;
                    }
                }
                // cbet opportunity tracking
                if phase == Phase::Flop && self.was_pfr && matches!(action, Action::Bet | Action::Raise | Action::AllIn) {
                    self.cbet_opportunities += 1;
                }
            }
            _ => {}
        }
    }

    /// call when player reaches showdown
    pub fn observe_showdown(&mut self, won: bool) {
        self.showdowns_seen += 1;
        if won { self.showdowns_won += 1; }
    }
}

/// tracks all opponents at the table
#[derive(Debug, Clone)]
pub struct TableProfiles {
    pub profiles: [PlayerProfile; MAX_SEATS],
}

impl Default for TableProfiles {
    fn default() -> Self {
        Self { profiles: [PlayerProfile::default(); MAX_SEATS] }
    }
}

impl TableProfiles {
    /// call when a new hand starts
    pub fn new_hand(&mut self, num_players: u8) {
        for i in 0..num_players as usize {
            self.profiles[i].new_hand();
        }
    }

    /// observe an action from a player
    pub fn observe(&mut self, seat: u8, action: Action, phase: Phase, is_facing_raise: bool) {
        self.profiles[seat as usize].observe_action(action, phase, is_facing_raise);
    }

    /// observe showdown result
    pub fn observe_showdown(&mut self, seat: u8, won: bool) {
        self.profiles[seat as usize].observe_showdown(won);
    }

    /// get features for all opponents (for neural net input)
    pub fn opponent_features(&self, hero_seat: u8, num_players: u8) -> [[f32; 16]; MAX_SEATS] {
        let mut features = [[0.0f32; 16]; MAX_SEATS];
        let mut idx = 0;
        for i in 0..num_players as usize {
            if i != hero_seat as usize {
                features[idx] = self.profiles[i].to_features();
                idx += 1;
            }
        }
        features
    }

    /// classify a specific player
    pub fn classify(&self, seat: u8) -> PlayerType {
        self.profiles[seat as usize].classify()
    }
}

impl GameState {
    pub fn new(rules: Rules, num_players: u8) -> Self {
        let n = (num_players as usize).min(MAX_SEATS).max(2);
        let mut stacks = [0u32; MAX_SEATS];
        let mut seat_state = [SeatState::Empty; MAX_SEATS];
        for i in 0..n {
            stacks[i] = rules.buyin;
            seat_state[i] = SeatState::Active;
        }
        Self {
            phase: Phase::Preflop,
            rules,
            num_players: n as u8,
            hand_number: 0,
            button: 0,
            stacks,
            pot: 0,
            bets: [0; MAX_SEATS],
            seat_state,
            cards: [[0; 2]; MAX_SEATS],
            community: [0; MAX_COMMUNITY],
            community_count: 0,
            acting_seat: 0,
            round_actions: 0,
            last_aggressor: 255,
            action_count: 0,
            last_action_hash: [0; 32],
            rake: 0,
        }
    }

    /// number of active (not folded/empty/sitting-out) players in this hand
    pub fn active_count(&self) -> u8 {
        (0..self.num_players as usize)
            .filter(|&i| matches!(self.seat_state[i], SeatState::Active | SeatState::AllIn))
            .count() as u8
    }

    /// next active seat after `seat` (wraps around)
    fn next_active(&self, seat: u8) -> u8 {
        let n = self.num_players as usize;
        let mut s = (seat as usize + 1) % n;
        for _ in 0..n {
            if matches!(self.seat_state[s], SeatState::Active | SeatState::AllIn) {
                return s as u8;
            }
            s = (s + 1) % n;
        }
        seat // shouldn't happen
    }

    /// small blind seat (next active after button)
    fn sb_seat(&self) -> u8 {
        if self.num_players == 2 {
            self.button // heads-up: button is SB
        } else {
            self.next_active(self.button)
        }
    }

    /// big blind seat (next active after SB)
    fn bb_seat(&self) -> u8 {
        self.next_active(self.sb_seat())
    }

    /// first to act preflop (UTG = next after BB, or SB in heads-up)
    fn first_preflop(&self) -> u8 {
        if self.num_players == 2 {
            self.sb_seat() // heads-up: SB acts first
        } else {
            self.next_active(self.bb_seat())
        }
    }

    /// first to act postflop (SB, or first active after button)
    fn first_postflop(&self) -> u8 {
        self.next_active(self.button)
    }

    /// sit a player out (they auto-fold, blinds skip them)
    pub fn sit_out(&mut self, seat: u8) {
        if (seat as usize) < self.num_players as usize {
            self.seat_state[seat as usize] = SeatState::SittingOut;
        }
    }

    /// sit a player back in
    pub fn sit_in(&mut self, seat: u8) {
        if (seat as usize) < self.num_players as usize && self.stacks[seat as usize] > 0 {
            self.seat_state[seat as usize] = SeatState::Active;
        }
    }

    /// deal a new hand. cards_per_seat: [[c0, c1]; num_players], community: [5]
    pub fn deal(&mut self, all_cards: &[[u8; 2]], community: [u8; 5]) {
        self.hand_number += 1;
        self.phase = Phase::Preflop;
        self.community = community;
        self.community_count = 0;
        self.pot = 0;
        self.bets = [0; MAX_SEATS];
        self.round_actions = 0;
        self.last_aggressor = 255;
        self.action_count = 0;
        // NOTE: rake accumulates across the session, not reset per hand

        // reset seat states for new hand
        for i in 0..self.num_players as usize {
            if self.seat_state[i] != SeatState::SittingOut && self.seat_state[i] != SeatState::Empty {
                if self.stacks[i] > 0 {
                    self.seat_state[i] = SeatState::Active;
                } else {
                    self.seat_state[i] = SeatState::SittingOut; // busted
                }
            }
            if i < all_cards.len() {
                self.cards[i] = all_cards[i];
            }
        }

        // post blinds
        let sb = self.sb_seat() as usize;
        let bb = self.bb_seat() as usize;
        let sb_amount = self.rules.small_blind.min(self.stacks[sb]);
        let bb_amount = self.rules.big_blind.min(self.stacks[bb]);
        self.stacks[sb] -= sb_amount;
        self.stacks[bb] -= bb_amount;
        self.bets[sb] = sb_amount;
        self.bets[bb] = bb_amount;
        self.pot = sb_amount + bb_amount;

        self.acting_seat = self.first_preflop();
    }

    /// apply a signed action
    pub fn apply(&mut self, action: &SignedAction) -> Result<ActionResult, &'static str> {
        // E5: only accept actions during betting phases
        if !matches!(self.phase, Phase::Preflop | Phase::Flop | Phase::Turn | Phase::River) {
            return Err("not in betting phase");
        }
        if action.seat as usize >= self.num_players as usize {
            return Err("invalid seat");
        }
        if action.seat != self.acting_seat {
            return Err("not your turn");
        }
        if !matches!(self.seat_state[action.seat as usize], SeatState::Active) {
            return Err("seat not active");
        }
        // E4: always enforce sequence (no seq=0 bypass)
        if action.seq != 0 && action.seq != self.action_count + 1 {
            return Err("wrong sequence");
        }

        let seat = action.seat as usize;
        let max_bet = self.bets.iter().take(self.num_players as usize).copied().max().unwrap_or(0);

        match action.action {
            Action::Fold => {
                self.seat_state[seat] = SeatState::Folded;
                self.action_count += 1;

                // check if only one player remains
                if self.active_count() == 1 {
                    // find the winner
                    let winner = (0..self.num_players as usize)
                        .find(|&i| matches!(self.seat_state[i], SeatState::Active | SeatState::AllIn))
                        .unwrap_or(0);
                    let payout = self.collect_rake();
                    self.stacks[winner] += payout;
                    self.pot = 0;
                    self.phase = Phase::Settled;
                    self.button = self.next_active(self.button);
                    return Ok(ActionResult {
                        valid: true, hand_over: true,
                        winner: winner as u8, payout, advance_phase: false,
                    });
                }

                self.acting_seat = self.next_active_in_round(action.seat);
                return Ok(ActionResult {
                    valid: true, hand_over: false,
                    winner: 255, payout: 0, advance_phase: false,
                });
            }

            Action::Check => {
                if self.bets[seat] < max_bet {
                    return Err("cannot check when facing a bet");
                }
            }

            Action::Call => {
                let to_call = max_bet.saturating_sub(self.bets[seat]);
                let actual = to_call.min(self.stacks[seat]);
                self.stacks[seat] -= actual;
                self.bets[seat] += actual;
                self.pot += actual;
                // if calling puts us all-in, mark it
                if self.stacks[seat] == 0 {
                    self.seat_state[seat] = SeatState::AllIn;
                }
            }

            Action::Bet | Action::Raise => {
                if action.amount == 0 { return Err("bet amount must be > 0"); }
                let amount = action.amount.min(self.stacks[seat]);
                if amount < self.rules.big_blind && amount < self.stacks[seat] {
                    return Err("raise below minimum");
                }
                self.stacks[seat] -= amount;
                self.bets[seat] += amount;
                self.pot += amount;
                // H6: if stack hits 0 from a bet/raise, mark as all-in
                if self.stacks[seat] == 0 {
                    self.seat_state[seat] = SeatState::AllIn;
                }
            }

            Action::AllIn => {
                let amount = self.stacks[seat];
                self.stacks[seat] = 0;
                self.bets[seat] += amount;
                self.pot += amount;
                self.seat_state[seat] = SeatState::AllIn;
            }
        }

        self.action_count += 1;
        self.round_actions += 1;

        if matches!(action.action, Action::Bet | Action::Raise | Action::AllIn) {
            self.last_aggressor = seat as u8;
            self.round_actions = 1;
        }

        // check if all remaining players are all-in or only one has chips
        let active_with_chips = (0..self.num_players as usize)
            .filter(|&i| matches!(self.seat_state[i], SeatState::Active) && self.stacks[i] > 0)
            .count();

        // if nobody can act anymore (all all-in or folded), skip to showdown
        if active_with_chips == 0 {
            self.equalize_bets();
            self.phase = Phase::Showdown;
            self.community_count = 5;
            return Ok(ActionResult {
                valid: true, hand_over: true,
                winner: 255, payout: 0, advance_phase: true,
            });
        }

        // advance to next active player
        self.acting_seat = self.next_active_in_round(action.seat);

        // check if round is complete
        if self.is_round_complete(action) {
            self.advance_phase();
        }

        Ok(ActionResult {
            valid: true,
            hand_over: self.phase == Phase::Showdown,
            winner: 255,
            payout: 0,
            advance_phase: self.phase != Phase::Preflop || self.community_count > 0,
        })
    }

    /// check if the current betting round is complete
    fn is_round_complete(&self, last_action: &SignedAction) -> bool {
        // all ACTIVE (not all-in, not folded) players must have equal bets
        let active_bets: Vec<u32> = (0..self.num_players as usize)
            .filter(|&i| self.seat_state[i] == SeatState::Active)
            .map(|i| self.bets[i])
            .collect();
        if active_bets.is_empty() { return true; } // everyone all-in or folded
        let all_equal = active_bets.iter().all(|&b| b == active_bets[0]);
        let was_passive = matches!(last_action.action, Action::Check | Action::Call);
        // count only active players (not all-in) for round completion
        let active_non_allin = (0..self.num_players as usize)
            .filter(|&i| self.seat_state[i] == SeatState::Active && self.stacks[i] > 0)
            .count() as u8;
        all_equal && was_passive && self.round_actions >= active_non_allin.max(2)
    }

    /// next active player who can still act (not folded, not all-in)
    fn next_active_in_round(&self, after: u8) -> u8 {
        let n = self.num_players as usize;
        let mut s = (after as usize + 1) % n;
        for _ in 0..n {
            if self.seat_state[s] == SeatState::Active && self.stacks[s] > 0 {
                return s as u8;
            }
            s = (s + 1) % n;
        }
        after
    }

    /// equalize bets into pot, handling multi-level side pots.
    ///
    /// for N>2 players with different all-in amounts, excess chips
    /// above what each player can match are returned to their stacks.
    ///
    /// example: A=100, B=500, C=1000 all-in
    ///   main pot: 3×100 = 300 (A,B,C eligible)
    ///   side pot 1: 2×400 = 800 (B,C eligible)
    ///   C gets 500 back (no one to compete against above B's level)
    fn equalize_bets(&mut self) {
        let n = self.num_players as usize;

        // collect all unique bet levels from active/all-in players, sorted ascending
        let mut levels: Vec<u32> = (0..n)
            .filter(|&i| matches!(self.seat_state[i], SeatState::Active | SeatState::AllIn))
            .map(|i| self.bets[i])
            .collect();
        levels.sort_unstable();
        levels.dedup();

        if levels.is_empty() {
            self.bets = [0; MAX_SEATS];
            return;
        }

        // for each level, only keep what can be matched
        // excess above the highest contested level goes back
        let max_contested = if levels.len() >= 2 {
            // the second-highest level is the most any player needs to match
            // the highest player gets excess back if they're the only one at that level
            let highest = *levels.last().unwrap();
            let second = levels[levels.len() - 2];
            let count_at_highest = (0..n)
                .filter(|&i| matches!(self.seat_state[i], SeatState::Active | SeatState::AllIn) && self.bets[i] == highest)
                .count();
            if count_at_highest == 1 {
                second // only one player at top → return excess above second
            } else {
                highest // multiple at top → all contested
            }
        } else {
            levels[0] // only one level — everyone matched
        };

        // return excess to players who bet above max contested
        for i in 0..n {
            if self.bets[i] > max_contested {
                let excess = self.bets[i] - max_contested;
                self.stacks[i] += excess;
                self.pot -= excess;
            }
        }
        self.bets = [0; MAX_SEATS];
    }

    fn advance_phase(&mut self) {
        self.bets = [0; MAX_SEATS];
        self.round_actions = 0;
        self.last_aggressor = 255;

        // how many players can still act?
        let active_with_chips = (0..self.num_players as usize)
            .filter(|&i| self.seat_state[i] == SeatState::Active && self.stacks[i] > 0)
            .count();

        match self.phase {
            Phase::Preflop => { self.phase = Phase::Flop; self.community_count = 3; }
            Phase::Flop => { self.phase = Phase::Turn; self.community_count = 4; }
            Phase::Turn => { self.phase = Phase::River; self.community_count = 5; }
            Phase::River => { self.phase = Phase::Showdown; }
            _ => {}
        }

        // if ≤1 player can act (rest all-in/folded), skip all remaining phases to showdown
        if active_with_chips <= 1 && self.phase != Phase::Showdown {
            self.equalize_bets();
            self.phase = Phase::Showdown;
            self.community_count = 5;
            return;
        }

        // set first to act postflop
        self.acting_seat = self.first_postflop();
        // skip to next active player who has chips
        if self.seat_state[self.acting_seat as usize] != SeatState::Active
            || self.stacks[self.acting_seat as usize] == 0
        {
            self.acting_seat = self.next_active_in_round(self.acting_seat.wrapping_sub(1));
        }
    }

    /// collect rake from pot. returns the pot after rake.
    fn collect_rake(&mut self) -> u32 {
        if self.rules.rake_bps == 0 { return self.pot; }
        let mut rake = (self.pot as u64 * self.rules.rake_bps as u64 / 10000) as u32;
        if self.rules.rake_cap > 0 { rake = rake.min(self.rules.rake_cap); }
        self.rake += rake;
        self.pot - rake
    }

    /// evaluate showdown — proper poker hand ranking, N players
    pub fn showdown(&mut self) -> u8 {
        // E6: verify community cards are set
        debug_assert!(self.community_count == 5, "showdown requires 5 community cards");
        // validate card range (0-51)
        for i in 0..5 {
            debug_assert!(self.community[i] < 52, "invalid community card: {}", self.community[i]);
        }

        let mut best_score = 0u32;
        let mut winners: [bool; MAX_SEATS] = [false; MAX_SEATS];
        let mut winner_count = 0u8;

        for i in 0..self.num_players as usize {
            if !matches!(self.seat_state[i], SeatState::Active | SeatState::AllIn) { continue; }
            let score = self.best_hand(i);
            if score > best_score {
                best_score = score;
                winners = [false; MAX_SEATS];
                winners[i] = true;
                winner_count = 1;
            } else if score == best_score {
                winners[i] = true;
                winner_count += 1;
            }
        }

        let payout = self.collect_rake();

        if winner_count > 1 {
            // split pot
            let share = payout / winner_count as u32;
            let remainder = payout % winner_count as u32;
            let mut first = true;
            for i in 0..self.num_players as usize {
                if winners[i] {
                    self.stacks[i] += share + if first { remainder } else { 0 };
                    first = false;
                }
            }
        } else {
            for i in 0..self.num_players as usize {
                if winners[i] { self.stacks[i] += payout; }
            }
        }

        self.pot = 0;
        self.phase = Phase::Settled;
        // rotate button to next active player
        self.button = self.next_active(self.button);

        // return first winner seat
        (0..self.num_players as usize).find(|&i| winners[i]).unwrap_or(0) as u8
    }

    fn best_hand(&self, seat: usize) -> u32 {
        let mut all7 = [0u8; 7];
        all7[0] = self.cards[seat][0];
        all7[1] = self.cards[seat][1];
        for i in 0..5 { all7[2 + i] = self.community[i]; }

        let mut best = 0u32;
        for i in 0..7 {
            for j in (i + 1)..7 {
                let mut hand = [0u8; 5];
                let mut idx = 0;
                for k in 0..7 {
                    if k != i && k != j { hand[idx] = all7[k]; idx += 1; }
                }
                let score = eval_5(hand);
                if score > best { best = score; }
            }
        }
        best
    }
}

/// evaluate best 5-card hand from 2 hole cards + 5 community cards
pub fn best_hand_7(hole: [u8; 2], community: &[u8; 5]) -> u32 {
    let mut all7 = [0u8; 7];
    all7[0] = hole[0];
    all7[1] = hole[1];
    for i in 0..5 { all7[2 + i] = community[i]; }

    let mut best = 0u32;
    for i in 0..7 {
        for j in (i + 1)..7 {
            let mut hand = [0u8; 5];
            let mut idx = 0;
            for k in 0..7 {
                if k != i && k != j { hand[idx] = all7[k]; idx += 1; }
            }
            let score = eval_5(hand);
            if score > best { best = score; }
        }
    }
    best
}

// ============================================================================
// Hand evaluation
// ============================================================================

const HIGH_CARD: u32 = 0;
const PAIR: u32 = 1;
const TWO_PAIR: u32 = 2;
const TRIPS: u32 = 3;
const STRAIGHT: u32 = 4;
const FLUSH: u32 = 5;
const FULL_HOUSE: u32 = 6;
const QUADS: u32 = 7;
const STRAIGHT_FLUSH: u32 = 8;

pub fn eval_5(hand: [u8; 5]) -> u32 {
    let mut ranks = [0u8; 5];
    let mut suits = [0u8; 5];
    for i in 0..5 { ranks[i] = hand[i] % 13; suits[i] = hand[i] / 13; }
    ranks.sort_unstable();
    ranks.reverse();

    let is_flush = suits[0] == suits[1] && suits[1] == suits[2] && suits[2] == suits[3] && suits[3] == suits[4];
    let is_straight = is_straight_check(&ranks);
    let is_wheel = ranks == [12, 3, 2, 1, 0];

    if is_flush && (is_straight || is_wheel) {
        return (STRAIGHT_FLUSH << 20) | if is_wheel { 3 } else { ranks[0] as u32 };
    }

    let mut freq = [0u8; 13];
    for &r in &ranks { freq[r as usize] += 1; }

    let mut quads_rank = 0u8;
    let mut trips_rank = 0u8;
    let mut pairs = [0u8; 2];
    let mut pair_count = 0usize;
    let mut kickers = [0u8; 5];
    let mut kick_idx = 0;

    for r in (0..13u8).rev() {
        match freq[r as usize] {
            4 => quads_rank = r + 1,
            3 => trips_rank = r + 1,
            2 => { if pair_count < 2 { pairs[pair_count] = r + 1; pair_count += 1; } }
            1 => { if kick_idx < 5 { kickers[kick_idx] = r; kick_idx += 1; } }
            _ => {}
        }
    }

    if quads_rank > 0 {
        return (QUADS << 20) | ((quads_rank as u32 - 1) << 4) | kickers[0] as u32;
    }
    if trips_rank > 0 && pair_count > 0 {
        return (FULL_HOUSE << 20) | ((trips_rank as u32 - 1) << 4) | (pairs[0] as u32 - 1);
    }
    if is_flush { return (FLUSH << 20) | kicker_score(&ranks); }
    if is_straight { return (STRAIGHT << 20) | ranks[0] as u32; }
    if is_wheel { return (STRAIGHT << 20) | 3; }
    if trips_rank > 0 {
        return (TRIPS << 20) | ((trips_rank as u32 - 1) << 8) | (kickers[0] as u32) << 4 | kickers[1] as u32;
    }
    if pair_count >= 2 {
        return (TWO_PAIR << 20) | ((pairs[0] as u32 - 1) << 8) | ((pairs[1] as u32 - 1) << 4) | kickers[0] as u32;
    }
    if pair_count == 1 {
        return (PAIR << 20) | ((pairs[0] as u32 - 1) << 12) | (kickers[0] as u32) << 8 | (kickers[1] as u32) << 4 | kickers[2] as u32;
    }
    (HIGH_CARD << 20) | kicker_score(&ranks)
}

fn kicker_score(ranks: &[u8; 5]) -> u32 {
    (ranks[0] as u32) << 16 | (ranks[1] as u32) << 12 | (ranks[2] as u32) << 8 | (ranks[3] as u32) << 4 | ranks[4] as u32
}

fn is_straight_check(sorted_desc: &[u8; 5]) -> bool {
    sorted_desc[0].saturating_sub(sorted_desc[4]) == 4 &&
    sorted_desc[0] != sorted_desc[1] && sorted_desc[1] != sorted_desc[2] &&
    sorted_desc[2] != sorted_desc[3] && sorted_desc[3] != sorted_desc[4]
}

// ============================================================================
// WASM bindings (heads-up convenience wrapper, delegates to N-seat engine)
// ============================================================================

