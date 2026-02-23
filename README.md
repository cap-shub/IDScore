# IDScore Protocol

A decentralized identity scoring protocol built on Stacks, enabling oracle-based reputation assessment for identity providers with on-chain credential issuance and dispute resolution.

---

## Table of Contents

- [Admin Controls](#admin-controls)
- [Protocol Controls](#protocol-controls)
- [Oracle Management](#oracle-management)
- [Identity Provider Management](#identity-provider-management)
- [Oracle Score Reporting](#oracle-score-reporting)
- [Score Aggregation](#score-aggregation)
- [Identity Issuance](#identity-issuance)
- [Dispute Mechanism](#dispute-mechanism)
- [Read-Only Functions](#read-only-functions)
- [Error Codes](#error-codes)
- [Installation](#installation)
- [Deployment](#deployment)

---

## Admin Controls

### `add-admin`

```clarity
(add-admin (address principal))
```

Grants admin privileges to the specified address. Only callable by the contract owner.

### `remove-admin`

```clarity
(remove-admin (address principal))
```

Revokes admin privileges from the specified address. Only callable by the contract owner.

---

## Protocol Controls

### `pause-protocol`

```clarity
(pause-protocol)
```

Pauses all state-changing operations. Callable by the owner or any admin.

### `unpause-protocol`

```clarity
(unpause-protocol)
```

Resumes protocol operations. Callable by the contract owner only.

---

## Oracle Management

### `register-oracle`

```clarity
(register-oracle (name (string-ascii 64)))
```

Registers the caller as an oracle. Transfers `STAKE-MINIMUM` (1 STX) from the caller to the contract as a security deposit. Returns the assigned oracle ID.

### `deactivate-oracle`

```clarity
(deactivate-oracle (oracle-id uint))
```

Deactivates an oracle and returns its staked STX to the oracle's address. Callable by the oracle itself, the owner, or an admin.

### `top-up-oracle-stake`

```clarity
(top-up-oracle-stake (oracle-id uint) (amount uint))
```

Adds additional STX stake to an existing oracle registration. Only the oracle's own address may call this.

---

## Identity Provider Management

### `register-provider`

```clarity
(register-provider (name (string-ascii 64)) (url (string-ascii 128)))
```

Registers the caller as an identity provider. Initial scores are set to zero. Returns the assigned provider ID.

### `suspend-provider`

```clarity
(suspend-provider (provider-id uint) (reason (string-ascii 128)))
```

Temporarily suspends a provider, preventing new score reports and identity issuance. Callable by owner or admin.

### `reinstate-provider`

```clarity
(reinstate-provider (provider-id uint))
```

Lifts a suspension and restores a provider to active status. Callable by owner or admin.

### `revoke-provider`

```clarity
(revoke-provider (provider-id uint) (reason (string-ascii 128)))
```

Permanently revokes a provider. This action is irreversible. Callable by the contract owner only.

---

## Oracle Score Reporting

### `submit-score-report`

```clarity
(submit-score-report
  (provider-id    uint)
  (accuracy-score uint)
  (security-score uint)
  (liveness-score uint)
  (evidence-hash  (buff 32)))
```

Submits an oracle's score report for a provider in the current epoch. Constraints:

- Each oracle may submit exactly one report per provider per epoch.
- All scores must be in the range `0–10000` (basis points).
- The `evidence-hash` is a 32-byte hash of off-chain evidence data.
- Both the provider and the oracle must be active and registered.

---

## Score Aggregation

### `finalize-epoch-scores`

```clarity
(finalize-epoch-scores
  (provider-id uint)
  (epoch        uint)
  (oracle-ids   (list 10 uint)))
```

Aggregates score reports from the supplied oracle IDs for the given provider and epoch. Requires a minimum of 3 valid reports. The composite score is computed as:

```
composite = (accuracy × 40 + security × 40 + liveness × 20) / 100
```

Writes the result to the provider record. Callable by owner or admin.

---

## Identity Issuance

### `issue-identity`

```clarity
(issue-identity
  (subject         principal)
  (provider-id     uint)
  (credential-hash (buff 32))
  (expires-at      uint))
```

Issues an on-chain identity record for a subject. Must be called by the registered address of an active provider. The `credential-hash` is a 32-byte hash of the off-chain credential document. Set `expires-at` to `u0` for a non-expiring credential. Captures the provider's current composite score as a snapshot. Returns the assigned identity ID.

### `revoke-identity`

```clarity
(revoke-identity (identity-id uint) (reason (string-ascii 128)))
```

Marks an identity record as revoked. Callable by the issuing provider, the contract owner, or an admin.

---

## Dispute Mechanism

### `open-dispute`

```clarity
(open-dispute
  (oracle-id     uint)
  (provider-id   uint)
  (epoch         uint)
  (reason        (string-ascii 256))
  (evidence-hash (buff 32)))
```

Opens a dispute against a specific oracle report. Requires the caller to transfer a `DISPUTE-BOND` of 0.5 STX to the contract. The targeted score report must exist. Returns the assigned dispute ID.

### `resolve-dispute`

```clarity
(resolve-dispute (dispute-id uint) (uphold bool))
```

Resolves an open dispute. Callable by owner or admin.

- **Upheld** (`uphold = true`): Slashes 20% of the oracle's stake. The dispute opener receives their bond back plus half the slashed amount. The oracle is deactivated if its remaining stake reaches zero.
- **Rejected** (`uphold = false`): The dispute bond is forfeited to the treasury. The oracle's `disputes-won` counter is incremented.

---

## Read-Only Functions

### Provider Queries

| Function | Parameters | Returns |
|---|---|---|
| `get-provider` | `(provider-id uint)` | Full provider record or `none` |
| `get-provider-by-address` | `(address principal)` | Full provider record or `none` |
| `get-provider-score` | `(provider-id uint)` | Score tuple (composite, accuracy, security, liveness, last-updated, status) or error |

### Oracle Queries

| Function | Parameters | Returns |
|---|---|---|
| `get-oracle` | `(oracle-id uint)` | Full oracle record or `none` |
| `get-oracle-by-address` | `(address principal)` | Full oracle record or `none` |
| `get-score-report` | `(oracle-id uint) (provider-id uint) (epoch uint)` | Score report record or `none` |
| `get-epoch-report-count` | `(provider-id uint) (epoch uint)` | Number of reports submitted for the epoch |

### Identity Queries

| Function | Parameters | Returns |
|---|---|---|
| `get-identity` | `(identity-id uint)` | Full identity record or `none` |
| `get-identity-by-subject` | `(subject principal) (provider-id uint)` | Full identity record or `none` |
| `is-identity-valid` | `(subject principal) (provider-id uint)` | `(ok true)` if non-revoked and non-expired, `(ok false)` otherwise, or error |

### Dispute Queries

| Function | Parameters | Returns |
|---|---|---|
| `get-dispute` | `(dispute-id uint)` | Full dispute record or `none` |

### Protocol State

| Function | Parameters | Returns |
|---|---|---|
| `get-protocol-state` | none | Tuple: paused flag, next IDs, treasury balance, current epoch |
| `get-current-epoch` | none | Current epoch number derived from block height |

---

## Error Codes

| Code | Constant | Description |
|---|---|---|
| `u100` | `ERR-NOT-OWNER` | Caller is not the contract owner |
| `u101` | `ERR-NOT-AUTHORIZED` | Caller lacks required permissions |
| `u102` | `ERR-PROVIDER-NOT-FOUND` | Provider ID does not exist |
| `u103` | `ERR-PROVIDER-EXISTS` | Address is already registered as a provider |
| `u104` | `ERR-ORACLE-NOT-FOUND` | Oracle ID does not exist |
| `u105` | `ERR-ORACLE-EXISTS` | Address is already registered as an oracle |
| `u106` | `ERR-ORACLE-NOT-ACTIVE` | Oracle is deactivated |
| `u107` | `ERR-INVALID-SCORE` | Score exceeds maximum of 10000 basis points |
| `u108` | `ERR-INVALID-WEIGHT` | Invalid weight parameter |
| `u109` | `ERR-ALREADY-ATTESTED` | Oracle has already submitted a report for this provider/epoch |
| `u110` | `ERR-NOT-ENOUGH-ORACLES` | Fewer than 3 valid oracle reports available |
| `u111` | `ERR-IDENTITY-NOT-FOUND` | Identity ID does not exist |
| `u112` | `ERR-IDENTITY-EXISTS` | Subject already has an identity from this provider |
| `u113` | `ERR-PROVIDER-SUSPENDED` | Provider is suspended or not active |
| `u114` | `ERR-INVALID-PARAM` | Invalid parameter value |
| `u115` | `ERR-DISPUTE-NOT-FOUND` | Dispute ID does not exist |
| `u116` | `ERR-DISPUTE-CLOSED` | Dispute is already resolved |
| `u117` | `ERR-INSUFFICIENT-STAKE` | Caller has insufficient STX balance to stake |

---

## Installation

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) v2.x or later
- [Node.js](https://nodejs.org) v18 or later (optional, for integration tests)

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/your-org/idscore.git
   cd idscore
   ```

2. Install Clarinet if not already installed:

   ```bash
   brew install clarinet
   ```

   Or via the [official installer](https://github.com/hirosystems/clarinet#installation).

3. Verify the project structure:

   ```bash
   clarinet check
   ```

4. Run the test suite:

   ```bash
   clarinet test
   ```

---

## Deployment

### Local Devnet

Start a local Stacks devnet with the contract pre-deployed:

```bash
clarinet devnet start
```

The contract will be deployed to the address defined in `Clarinet.toml` under `[contracts.idscore]`.

### Testnet

1. Request testnet STX from the [Stacks faucet](https://explorer.hiro.so/sandbox/faucet?chain=testnet).

2. Configure your deployer account in `settings/Testnet.toml`:

   ```toml
   [accounts.deployer]
   mnemonic = "your mnemonic here"
   ```

3. Deploy:

   ```bash
   clarinet deployments apply --testnet
   ```

4. Confirm on the [Stacks Testnet Explorer](https://explorer.hiro.so/?chain=testnet).

### Mainnet

1. Configure your deployer account in `settings/Mainnet.toml` with a funded mainnet wallet.

2. Generate and review the deployment plan:

   ```bash
   clarinet deployments generate --mainnet
   ```

3. Apply the deployment:

   ```bash
   clarinet deployments apply --mainnet
   ```