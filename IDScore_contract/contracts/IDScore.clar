;; IDScore - Oracle Protocol for Digital Identity Provider Scoring
;; Scores identity providers on accuracy and security to form a verifiable Web3 identity primitive.

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

(define-constant ERR-NOT-OWNER              (err u100))
(define-constant ERR-NOT-AUTHORIZED         (err u101))
(define-constant ERR-PROVIDER-NOT-FOUND     (err u102))
(define-constant ERR-PROVIDER-EXISTS        (err u103))
(define-constant ERR-ORACLE-NOT-FOUND       (err u104))
(define-constant ERR-ORACLE-EXISTS          (err u105))
(define-constant ERR-ORACLE-NOT-ACTIVE      (err u106))
(define-constant ERR-INVALID-SCORE          (err u107))
(define-constant ERR-INVALID-WEIGHT         (err u108))
(define-constant ERR-ALREADY-ATTESTED       (err u109))
(define-constant ERR-NOT-ENOUGH-ORACLES     (err u110))
(define-constant ERR-IDENTITY-NOT-FOUND     (err u111))
(define-constant ERR-IDENTITY-EXISTS        (err u112))
(define-constant ERR-PROVIDER-SUSPENDED     (err u113))
(define-constant ERR-INVALID-PARAM          (err u114))
(define-constant ERR-DISPUTE-NOT-FOUND      (err u115))
(define-constant ERR-DISPUTE-CLOSED         (err u116))
(define-constant ERR-INSUFFICIENT-STAKE     (err u117))

;; Score boundaries (basis points: 0-10000)
(define-constant MAX-SCORE             u10000)
(define-constant MIN-ORACLES-REQUIRED  u3)
(define-constant STAKE-MINIMUM         u1000000)   ;; 1 STX in micro-STX
(define-constant SLASH-PERCENT         u20)        ;; 20% stake slash on dispute resolution against oracle
(define-constant DISPUTE-BOND          u500000)    ;; 0.5 STX bond to open a dispute
(define-constant SCORE-DECAY-BLOCKS    u1440)      ;; ~10 days on Stacks (144 blocks/day)

;; Provider status codes
(define-constant STATUS-ACTIVE    u1)
(define-constant STATUS-SUSPENDED u2)
(define-constant STATUS-REVOKED   u3)

;; ============================================================
;; DATA VARS
;; ============================================================

(define-data-var next-provider-id  uint u1)
(define-data-var next-oracle-id    uint u1)
(define-data-var next-identity-id  uint u1)
(define-data-var next-dispute-id   uint u1)
(define-data-var protocol-paused   bool false)
(define-data-var treasury-balance  uint u0)

;; ============================================================
;; DATA MAPS
;; ============================================================

;; ---------- Oracle Registry ----------
(define-map oracles
  { oracle-id: uint }
  {
    address:       principal,
    name:          (string-ascii 64),
    stake:         uint,
    active:        bool,
    reports-made:  uint,
    disputes-won:  uint,
    disputes-lost: uint,
    registered-at: uint
  }
)

(define-map oracle-by-address
  { address: principal }
  { oracle-id: uint }
)

;; ---------- Identity Provider Registry ----------
(define-map providers
  { provider-id: uint }
  {
    address:         principal,
    name:            (string-ascii 64),
    url:             (string-ascii 128),
    status:          uint,
    composite-score: uint,          ;; aggregated score in basis points
    accuracy-score:  uint,
    security-score:  uint,
    liveness-score:  uint,
    report-count:    uint,
    last-updated:    uint,
    registered-at:   uint
  }
)

(define-map provider-by-address
  { address: principal }
  { provider-id: uint }
)

;; ---------- Identity Records ----------
(define-map identities
  { identity-id: uint }
  {
    subject:         principal,
    provider-id:     uint,
    credential-hash: (buff 32),     ;; hash of the off-chain credential document
    issued-at:       uint,
    expires-at:      uint,          ;; 0 = no expiry
    revoked:         bool,
    score-snapshot:  uint           ;; provider composite score at issuance
  }
)

(define-map identity-by-subject
  { subject: principal, provider-id: uint }
  { identity-id: uint }
)

;; ---------- Oracle Score Reports ----------
;; Each oracle submits one report per provider per epoch
(define-map score-reports
  { oracle-id: uint, provider-id: uint, epoch: uint }
  {
    accuracy-score: uint,
    security-score: uint,
    liveness-score: uint,
    evidence-hash:  (buff 32),
    submitted-at:   uint
  }
)

;; Track how many oracles have reported on a provider in an epoch
(define-map epoch-report-count
  { provider-id: uint, epoch: uint }
  { count: uint }
)

;; ---------- Disputes ----------
(define-map disputes
  { dispute-id: uint }
  {
    opener:        principal,
    oracle-id:     uint,
    provider-id:   uint,
    epoch:         uint,
    reason:        (string-ascii 256),
    evidence-hash: (buff 32),
    bond:          uint,
    resolved:      bool,
    upheld:        bool,            ;; true = dispute upheld, oracle slashed
    opened-at:     uint,
    resolved-at:   uint
  }
)

;; ---------- Governance: Authorised Admins ----------
(define-map admins
  { address: principal }
  { active: bool }
)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

(define-private (is-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

(define-private (is-admin)
  (default-to false (get active (map-get? admins { address: tx-sender })))
)

(define-private (is-owner-or-admin)
  (or (is-owner) (is-admin))
)

(define-private (assert-not-paused)
  (ok (asserts! (not (var-get protocol-paused)) ERR-NOT-AUTHORIZED))
)

(define-private (current-epoch)
  ;; Epoch length = SCORE-DECAY-BLOCKS blocks
  (/ stacks-block-height SCORE-DECAY-BLOCKS)
)

(define-private (valid-score (s uint))
  (<= s MAX-SCORE)
)

;; Fold helper - accumulates scores from a single oracle report into running totals
(define-private (accumulate-oracle-scores
    (oracle-id uint)
    (state {
      provider-id:  uint,
      epoch:        uint,
      acc-sum:      uint,
      sec-sum:      uint,
      liv-sum:      uint,
      valid-count:  uint
    }))
  (let (
    (report (map-get? score-reports
      { oracle-id:   oracle-id,
        provider-id: (get provider-id state),
        epoch:       (get epoch state) }))
  )
    (match report
      r (merge state {
            acc-sum:     (+ (get acc-sum state)     (get accuracy-score r)),
            sec-sum:     (+ (get sec-sum state)     (get security-score r)),
            liv-sum:     (+ (get liv-sum state)     (get liveness-score r)),
            valid-count: (+ (get valid-count state) u1)
         })
      state  ;; no report found for this oracle - skip silently
    )
  )
)

;; ============================================================
;; ADMIN MANAGEMENT
;; ============================================================

(define-public (add-admin (address principal))
  (begin
    (asserts! (is-owner) ERR-NOT-OWNER)
    (map-set admins { address: address } { active: true })
    (print { event: "admin-added", address: address })
    (ok true)
  )
)

(define-public (remove-admin (address principal))
  (begin
    (asserts! (is-owner) ERR-NOT-OWNER)
    (map-set admins { address: address } { active: false })
    (print { event: "admin-removed", address: address })
    (ok true)
  )
)

;; ============================================================
;; PROTOCOL CONTROLS
;; ============================================================

(define-public (pause-protocol)
  (begin
    (asserts! (is-owner-or-admin) ERR-NOT-AUTHORIZED)
    (var-set protocol-paused true)
    (print { event: "protocol-paused", by: tx-sender })
    (ok true)
  )
)

(define-public (unpause-protocol)
  (begin
    (asserts! (is-owner) ERR-NOT-OWNER)
    (var-set protocol-paused false)
    (print { event: "protocol-unpaused", by: tx-sender })
    (ok true)
  )
)

;; ============================================================
;; ORACLE MANAGEMENT
;; ============================================================

;; Register as an oracle by staking STAKE-MINIMUM micro-STX
(define-public (register-oracle (name (string-ascii 64)))
  (let (
    (oracle-id (var-get next-oracle-id))
  )
    (try! (assert-not-paused))
    (asserts! (is-none (map-get? oracle-by-address { address: tx-sender })) ERR-ORACLE-EXISTS)
    (asserts! (>= (stx-get-balance tx-sender) STAKE-MINIMUM) ERR-INSUFFICIENT-STAKE)
    (try! (stx-transfer? STAKE-MINIMUM tx-sender (as-contract tx-sender)))
    (map-set oracles
      { oracle-id: oracle-id }
      {
        address:       tx-sender,
        name:          name,
        stake:         STAKE-MINIMUM,
        active:        true,
        reports-made:  u0,
        disputes-won:  u0,
        disputes-lost: u0,
        registered-at: stacks-block-height
      }
    )
    (map-set oracle-by-address { address: tx-sender } { oracle-id: oracle-id })
    (var-set next-oracle-id (+ oracle-id u1))
    (print { event: "oracle-registered", oracle-id: oracle-id, address: tx-sender, name: name })
    (ok oracle-id)
  )
)

;; Deactivate oracle and return its stake (owner/admin can also deactivate)
(define-public (deactivate-oracle (oracle-id uint))
  (let (
    (oracle (unwrap! (map-get? oracles { oracle-id: oracle-id }) ERR-ORACLE-NOT-FOUND))
  )
    (asserts! (or (is-eq tx-sender (get address oracle)) (is-owner-or-admin)) ERR-NOT-AUTHORIZED)
    (map-set oracles { oracle-id: oracle-id }
      (merge oracle { active: false })
    )
    (try! (as-contract (stx-transfer? (get stake oracle) tx-sender (get address oracle))))
    (print { event: "oracle-deactivated", oracle-id: oracle-id })
    (ok true)
  )
)

;; Increase stake for an existing oracle
(define-public (top-up-oracle-stake (oracle-id uint) (amount uint))
  (let (
    (oracle (unwrap! (map-get? oracles { oracle-id: oracle-id }) ERR-ORACLE-NOT-FOUND))
  )
    (asserts! (is-eq tx-sender (get address oracle)) ERR-NOT-AUTHORIZED)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set oracles { oracle-id: oracle-id }
      (merge oracle { stake: (+ (get stake oracle) amount) })
    )
    (print { event: "oracle-stake-topped-up", oracle-id: oracle-id, amount: amount })
    (ok true)
  )
)

;; ============================================================
;; IDENTITY PROVIDER MANAGEMENT
;; ============================================================

;; Register as an identity provider
(define-public (register-provider
    (name (string-ascii 64))
    (url  (string-ascii 128)))
  (let (
    (provider-id (var-get next-provider-id))
  )
    (try! (assert-not-paused))
    (asserts! (is-none (map-get? provider-by-address { address: tx-sender })) ERR-PROVIDER-EXISTS)
    (map-set providers
      { provider-id: provider-id }
      {
        address:         tx-sender,
        name:            name,
        url:             url,
        status:          STATUS-ACTIVE,
        composite-score: u0,
        accuracy-score:  u0,
        security-score:  u0,
        liveness-score:  u0,
        report-count:    u0,
        last-updated:    stacks-block-height,
        registered-at:   stacks-block-height
      }
    )
    (map-set provider-by-address { address: tx-sender } { provider-id: provider-id })
    (var-set next-provider-id (+ provider-id u1))
    (print { event: "provider-registered", provider-id: provider-id, address: tx-sender, name: name })
    (ok provider-id)
  )
)

;; Temporarily suspend a provider (admin action)
(define-public (suspend-provider (provider-id uint) (reason (string-ascii 128)))
  (let (
    (provider (unwrap! (map-get? providers { provider-id: provider-id }) ERR-PROVIDER-NOT-FOUND))
  )
    (asserts! (is-owner-or-admin) ERR-NOT-AUTHORIZED)
    (map-set providers { provider-id: provider-id }
      (merge provider { status: STATUS-SUSPENDED })
    )
    (print { event: "provider-suspended", provider-id: provider-id, reason: reason })
    (ok true)
  )
)

;; Lift a suspension and restore ACTIVE status
(define-public (reinstate-provider (provider-id uint))
  (let (
    (provider (unwrap! (map-get? providers { provider-id: provider-id }) ERR-PROVIDER-NOT-FOUND))
  )
    (asserts! (is-owner-or-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status provider) STATUS-SUSPENDED) ERR-INVALID-PARAM)
    (map-set providers { provider-id: provider-id }
      (merge provider { status: STATUS-ACTIVE })
    )
    (print { event: "provider-reinstated", provider-id: provider-id })
    (ok true)
  )
)

;; Permanently revoke a provider (owner only)
(define-public (revoke-provider (provider-id uint) (reason (string-ascii 128)))
  (let (
    (provider (unwrap! (map-get? providers { provider-id: provider-id }) ERR-PROVIDER-NOT-FOUND))
  )
    (asserts! (is-owner) ERR-NOT-OWNER)
    (map-set providers { provider-id: provider-id }
      (merge provider { status: STATUS-REVOKED })
    )
    (print { event: "provider-revoked", provider-id: provider-id, reason: reason })
    (ok true)
  )
)

;; ============================================================
;; ORACLE SCORE REPORTING
;; ============================================================

;; Submit accuracy, security, and liveness scores for a provider in the current epoch.
;; Each active oracle may submit exactly one report per provider per epoch.
(define-public (submit-score-report
    (provider-id    uint)
    (accuracy-score uint)
    (security-score uint)
    (liveness-score uint)
    (evidence-hash  (buff 32)))
  (let (
    (oracle-entry (unwrap! (map-get? oracle-by-address { address: tx-sender }) ERR-ORACLE-NOT-FOUND))
    (oracle-id    (get oracle-id oracle-entry))
    (oracle       (unwrap! (map-get? oracles { oracle-id: oracle-id }) ERR-ORACLE-NOT-FOUND))
    (provider     (unwrap! (map-get? providers { provider-id: provider-id }) ERR-PROVIDER-NOT-FOUND))
    (epoch        (current-epoch))
  )
    (try! (assert-not-paused))
    (asserts! (get active oracle) ERR-ORACLE-NOT-ACTIVE)
    (asserts! (is-eq (get status provider) STATUS-ACTIVE) ERR-PROVIDER-SUSPENDED)
    (asserts! (valid-score accuracy-score) ERR-INVALID-SCORE)
    (asserts! (valid-score security-score) ERR-INVALID-SCORE)
    (asserts! (valid-score liveness-score) ERR-INVALID-SCORE)
    ;; One report per oracle per provider per epoch
    (asserts!
      (is-none (map-get? score-reports { oracle-id: oracle-id, provider-id: provider-id, epoch: epoch }))
      ERR-ALREADY-ATTESTED
    )
    (map-set score-reports
      { oracle-id: oracle-id, provider-id: provider-id, epoch: epoch }
      {
        accuracy-score: accuracy-score,
        security-score: security-score,
        liveness-score: liveness-score,
        evidence-hash:  evidence-hash,
        submitted-at:   stacks-block-height
      }
    )
    ;; Update epoch report counter
    (let (
      (cur-count (default-to u0
        (get count (map-get? epoch-report-count { provider-id: provider-id, epoch: epoch }))))
    )
      (map-set epoch-report-count
        { provider-id: provider-id, epoch: epoch }
        { count: (+ cur-count u1) }
      )
    )
    ;; Increment oracle lifetime report tally
    (map-set oracles { oracle-id: oracle-id }
      (merge oracle { reports-made: (+ (get reports-made oracle) u1) })
    )
    (print {
      event:          "score-report-submitted",
      oracle-id:      oracle-id,
      provider-id:    provider-id,
      epoch:          epoch,
      accuracy-score: accuracy-score,
      security-score: security-score,
      liveness-score: liveness-score,
      evidence-hash:  evidence-hash
    })
    (ok true)
  )
)

;; ============================================================
;; SCORE AGGREGATION (admin-triggered per epoch)
;; ============================================================
;; Averages up to 10 oracle reports and writes the composite score.
;; Composite formula: 40 % accuracy + 40 % security + 20 % liveness.

(define-public (finalize-epoch-scores
    (provider-id uint)
    (epoch        uint)
    (oracle-ids   (list 10 uint)))
  (let (
    (provider (unwrap! (map-get? providers { provider-id: provider-id }) ERR-PROVIDER-NOT-FOUND))
    (n        (len oracle-ids))
  )
    (asserts! (is-owner-or-admin) ERR-NOT-AUTHORIZED)
    (asserts! (>= n MIN-ORACLES-REQUIRED) ERR-NOT-ENOUGH-ORACLES)

    (let (
      (totals (fold accumulate-oracle-scores oracle-ids
        {
          provider-id:  provider-id,
          epoch:        epoch,
          acc-sum:      u0,
          sec-sum:      u0,
          liv-sum:      u0,
          valid-count:  u0
        }
      ))
      (cnt (get valid-count totals))
    )
      (asserts! (>= cnt MIN-ORACLES-REQUIRED) ERR-NOT-ENOUGH-ORACLES)

      (let (
        (avg-acc (/ (get acc-sum totals) cnt))
        (avg-sec (/ (get sec-sum totals) cnt))
        (avg-liv (/ (get liv-sum totals) cnt))
        ;; 40 % accuracy + 40 % security + 20 % liveness
        (composite (/ (+ (* avg-acc u40) (+ (* avg-sec u40) (* avg-liv u20))) u100))
      )
        (map-set providers { provider-id: provider-id }
          (merge provider {
            composite-score: composite,
            accuracy-score:  avg-acc,
            security-score:  avg-sec,
            liveness-score:  avg-liv,
            report-count:    (+ (get report-count provider) cnt),
            last-updated:    stacks-block-height
          })
        )
        (print {
          event:        "epoch-scores-finalized",
          provider-id:  provider-id,
          epoch:        epoch,
          composite:    composite,
          accuracy:     avg-acc,
          security:     avg-sec,
          liveness:     avg-liv,
          oracle-count: cnt
        })
        (ok composite)
      )
    )
  )
)

;; ============================================================
;; IDENTITY ISSUANCE
;; ============================================================

;; A registered, active provider issues a verifiable identity record for a subject.
(define-public (issue-identity
    (subject         principal)
    (provider-id     uint)
    (credential-hash (buff 32))
    (expires-at      uint))
  (let (
    (provider    (unwrap! (map-get? providers { provider-id: provider-id }) ERR-PROVIDER-NOT-FOUND))
    (identity-id (var-get next-identity-id))
  )
    (try! (assert-not-paused))
    (asserts! (is-eq tx-sender (get address provider)) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status provider) STATUS-ACTIVE) ERR-PROVIDER-SUSPENDED)
    (asserts!
      (is-none (map-get? identity-by-subject { subject: subject, provider-id: provider-id }))
      ERR-IDENTITY-EXISTS
    )
    (map-set identities
      { identity-id: identity-id }
      {
        subject:         subject,
        provider-id:     provider-id,
        credential-hash: credential-hash,
        issued-at:       stacks-block-height,
        expires-at:      expires-at,
        revoked:         false,
        score-snapshot:  (get composite-score provider)
      }
    )
    (map-set identity-by-subject
      { subject: subject, provider-id: provider-id }
      { identity-id: identity-id }
    )
    (var-set next-identity-id (+ identity-id u1))
    (print {
      event:           "identity-issued",
      identity-id:     identity-id,
      subject:         subject,
      provider-id:     provider-id,
      credential-hash: credential-hash,
      score-snapshot:  (get composite-score provider)
    })
    (ok identity-id)
  )
)

;; Revoke an issued identity (provider or admin)
(define-public (revoke-identity (identity-id uint) (reason (string-ascii 128)))
  (let (
    (identity (unwrap! (map-get? identities { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
    (provider (unwrap! (map-get? providers { provider-id: (get provider-id identity) }) ERR-PROVIDER-NOT-FOUND))
  )
    (asserts!
      (or (is-eq tx-sender (get address provider)) (is-owner-or-admin))
      ERR-NOT-AUTHORIZED
    )
    (map-set identities { identity-id: identity-id }
      (merge identity { revoked: true })
    )
    (print { event: "identity-revoked", identity-id: identity-id, reason: reason })
    (ok true)
  )
)

;; ============================================================
;; DISPUTE MECHANISM
;; ============================================================

;; Open a dispute against a specific oracle report, posting a bond.
(define-public (open-dispute
    (oracle-id     uint)
    (provider-id   uint)
    (epoch         uint)
    (reason        (string-ascii 256))
    (evidence-hash (buff 32)))
  (let (
    (dispute-id (var-get next-dispute-id))
    (oracle-check    (unwrap! (map-get? oracles { oracle-id: oracle-id }) ERR-ORACLE-NOT-FOUND))
    (provider-check  (unwrap! (map-get? providers { provider-id: provider-id }) ERR-PROVIDER-NOT-FOUND))
    (report-check    (unwrap!
                  (map-get? score-reports { oracle-id: oracle-id, provider-id: provider-id, epoch: epoch })
                  ERR-ORACLE-NOT-FOUND))
  )
    (try! (assert-not-paused))
    (try! (stx-transfer? DISPUTE-BOND tx-sender (as-contract tx-sender)))
    (var-set treasury-balance (+ (var-get treasury-balance) DISPUTE-BOND))
    (map-set disputes
      { dispute-id: dispute-id }
      {
        opener:        tx-sender,
        oracle-id:     oracle-id,
        provider-id:   provider-id,
        epoch:         epoch,
        reason:        reason,
        evidence-hash: evidence-hash,
        bond:          DISPUTE-BOND,
        resolved:      false,
        upheld:        false,
        opened-at:     stacks-block-height,
        resolved-at:   u0
      }
    )
    (var-set next-dispute-id (+ dispute-id u1))
    (print {
      event:       "dispute-opened",
      dispute-id:  dispute-id,
      oracle-id:   oracle-id,
      provider-id: provider-id,
      epoch:       epoch,
      opener:      tx-sender
    })
    (ok dispute-id)
  )
)

;; Resolve a dispute: uphold = slash oracle + reward opener; reject = forfeit bond to treasury.
(define-public (resolve-dispute (dispute-id uint) (uphold bool))
  (let (
    (dispute (unwrap! (map-get? disputes { dispute-id: dispute-id }) ERR-DISPUTE-NOT-FOUND))
    (oracle  (unwrap! (map-get? oracles { oracle-id: (get oracle-id dispute) }) ERR-ORACLE-NOT-FOUND))
  )
    (asserts! (is-owner-or-admin) ERR-NOT-AUTHORIZED)
    (asserts! (not (get resolved dispute)) ERR-DISPUTE-CLOSED)

    (if uphold
      ;; Dispute upheld: slash oracle stake and reward the dispute opener
      (let (
        (slash-amount (/ (* (get stake oracle) SLASH-PERCENT) u100))
        (new-stake    (- (get stake oracle) slash-amount))
        (reward       (+ (get bond dispute) (/ slash-amount u2)))
      )
        (map-set oracles { oracle-id: (get oracle-id dispute) }
          (merge oracle {
            stake:         new-stake,
            disputes-lost: (+ (get disputes-lost oracle) u1),
            active:        (> new-stake u0)
          })
        )
        (var-set treasury-balance (- (var-get treasury-balance) (get bond dispute)))
        (try! (as-contract (stx-transfer? reward tx-sender (get opener dispute))))
        (print { event: "dispute-upheld", dispute-id: dispute-id, slash-amount: slash-amount, reward: reward })
        true
      )
      ;; Dispute rejected: bond stays in treasury, oracle reputation improves
      (begin
        (map-set oracles { oracle-id: (get oracle-id dispute) }
          (merge oracle { disputes-won: (+ (get disputes-won oracle) u1) })
        )
        (print { event: "dispute-rejected", dispute-id: dispute-id })
        true
      )
    )
    (map-set disputes { dispute-id: dispute-id }
      (merge dispute { resolved: true, upheld: uphold, resolved-at: stacks-block-height })
    )
    (ok true)
  )
)

;; ============================================================
;; READ-ONLY: PROVIDER QUERIES
;; ============================================================

(define-read-only (get-provider (provider-id uint))
  (map-get? providers { provider-id: provider-id })
)

(define-read-only (get-provider-by-address (address principal))
  (match (map-get? provider-by-address { address: address })
    entry (map-get? providers { provider-id: (get provider-id entry) })
    none
  )
)

(define-read-only (get-provider-score (provider-id uint))
  (match (map-get? providers { provider-id: provider-id })
    provider (ok {
      composite-score: (get composite-score provider),
      accuracy-score:  (get accuracy-score  provider),
      security-score:  (get security-score  provider),
      liveness-score:  (get liveness-score  provider),
      last-updated:    (get last-updated    provider),
      status:          (get status          provider)
    })
    ERR-PROVIDER-NOT-FOUND
  )
)

;; ============================================================
;; READ-ONLY: ORACLE QUERIES
;; ============================================================

(define-read-only (get-oracle (oracle-id uint))
  (map-get? oracles { oracle-id: oracle-id })
)

(define-read-only (get-oracle-by-address (address principal))
  (match (map-get? oracle-by-address { address: address })
    entry (map-get? oracles { oracle-id: (get oracle-id entry) })
    none
  )
)

(define-read-only (get-score-report (oracle-id uint) (provider-id uint) (epoch uint))
  (map-get? score-reports { oracle-id: oracle-id, provider-id: provider-id, epoch: epoch })
)

(define-read-only (get-epoch-report-count (provider-id uint) (epoch uint))
  (default-to u0 (get count (map-get? epoch-report-count { provider-id: provider-id, epoch: epoch })))
)

;; ============================================================
;; READ-ONLY: IDENTITY QUERIES
;; ============================================================

(define-read-only (get-identity (identity-id uint))
  (map-get? identities { identity-id: identity-id })
)

(define-read-only (get-identity-by-subject (subject principal) (provider-id uint))
  (match (map-get? identity-by-subject { subject: subject, provider-id: provider-id })
    entry (map-get? identities { identity-id: (get identity-id entry) })
    none
  )
)

;; Returns (ok true/false) indicating whether the identity is currently valid
(define-read-only (is-identity-valid (subject principal) (provider-id uint))
  (match (map-get? identity-by-subject { subject: subject, provider-id: provider-id })
    entry
      (match (map-get? identities { identity-id: (get identity-id entry) })
        identity
          (ok (and
            (not (get revoked identity))
            (or
              (is-eq (get expires-at identity) u0)
              (> (get expires-at identity) stacks-block-height)
            )
          ))
        ERR-IDENTITY-NOT-FOUND
      )
    ERR-IDENTITY-NOT-FOUND
  )
)

;; ============================================================
;; READ-ONLY: DISPUTE QUERIES
;; ============================================================

(define-read-only (get-dispute (dispute-id uint))
  (map-get? disputes { dispute-id: dispute-id })
)

;; ============================================================
;; READ-ONLY: PROTOCOL STATE
;; ============================================================

(define-read-only (get-protocol-state)
  {
    paused:           (var-get protocol-paused),
    next-provider-id: (var-get next-provider-id),
    next-oracle-id:   (var-get next-oracle-id),
    next-identity-id: (var-get next-identity-id),
    next-dispute-id:  (var-get next-dispute-id),
    treasury-balance: (var-get treasury-balance),
    current-epoch:    (current-epoch)
  }
)

(define-read-only (get-current-epoch)
  (current-epoch)
)
