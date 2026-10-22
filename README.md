# Lockbox

An end-to-end encrypted file storage and sharing system designed to keep data private and tamper-evident even when the storage server can't be trusted.

Lockbox assumes the server storing your data may be malicious: it can read, modify, or delete anything it holds. Everything stored on it is encrypted and authenticated, so an attacker can't learn file contents, learn who has access to what, or tamper with data without being detected.

---

## Features

- **Secure accounts**: passwords are hashed with Argon2, and usernames are stored as HMAC values, never in plaintext.
- **Encrypted file storage**: every file is encrypted and signed before it leaves the client.
- **Efficient appends**: appending writes only a new tail node, so bandwidth scales with the size of the append, not the size of the file.
- **Secure sharing**: invitations use hybrid encryption and digital signatures, so only the intended recipient can open them and tampering is detected.
- **One shared copy**: all users with access edit the same file, while each user keeps their own filename for it.
- **Full revocation**: revoked users lose access to the file's contents, its location, and its access tree.

---

## Architecture

Lockbox uses two untrusted storage services:

| Service       | Holds                                                         |
| ------------- | ------------------------------------------------------------- |
| **Datastore** | Encrypted user structs, file nodes, access trees, invitations |
| **Keystore**  | Public encryption keys and public signature-verification keys |

### 1. Users and Authentication

**Creating a user (`InitUser`)**

1. Check whether the username already exists. If it does and the password matches, return the existing user instead of creating a new one.
2. Otherwise, hash the username with HMAC and the password with Argon2, and store both in a `UserAuthenticate` struct under a deterministic UUID.
3. Generate the user's public/private encryption key pair and signing/verification key pair.
4. Store all user data in a `User` struct, then marshal, symmetrically encrypt, and save it to the Datastore.
5. Publish the public encryption key and the verification key to the Keystore.

**Logging in (`GetUser`)**

1. Hash the username and derive the deterministic UUID.
2. Fetch and unmarshal the stored credentials, then compare usernames with a constant-time HMAC comparison.
3. Verify the password against the stored Argon2 hash.
4. On success, derive the symmetric key, decrypt the `User` struct, and return it.

### 2. File Operations

**Storing a file (`StoreFile`)**

- If the file is new, generate a random, secret file ID and create the initial file node.
- Create an encrypted **access tree** for the file, recording who has access, the file ID, usernames, filenames, valid invitations, and a random padding value.
- The file's storage location is derived from `padding + Hash(fileID)`, so it can be moved later.
- File content is placed in a list node, marshaled, encrypted with a symmetric key, signed, and uploaded under a deterministic UUID.
- If the file already exists, its content is overwritten in place.

**Appending to a file (`AppendToFile`)**

- Fetch the file metadata and verify its integrity with HMAC.
- Write the new content to a fresh, randomly generated UUID.
- Record that UUID as the new **tail** of the linked list, so only the tail node and list header are updated on each append.

```
[Head] → [Node 1] → [Node 2] → ... → [Tail]
                                       ↑
                         each append adds a node here
```

**Loading a file (`LoadFile`)**

- Fetch and validate the file metadata.
- Walk the linked list from the head, decrypting and verifying each node, and assemble the full content in order.

### 3. Sharing and Revocation

**Creating an invitation (`CreateInvitation`)**

1. Confirm the file exists in the sender's namespace, refreshing the user data once if needed.
2. Build an invitation struct with the file ID and keys the recipient needs.
3. Encrypt the invitation with a fresh symmetric key.
4. Encrypt that symmetric key with the recipient's public key from the Keystore.
5. Sign the encrypted key with the sender's signing key.
6. Store the result under a UUID derived from the file and recipient.
7. Record the invitation pointer and recipient in the sender's node of the access tree, so invitations can be verified, changed, or cancelled later.

**Accepting an invitation (`AcceptInvitation`)**

1. Check that the invitation exists in the access tree and was issued to this recipient.
2. Fetch the invitation and verify the sender's signature using the Keystore.
3. Decrypt the symmetric key with the recipient's private key, then decrypt the invitation.
4. Check the invitation against the access tree to confirm the sender is allowed to share the file.
5. Reject the invitation if the recipient already has a file with the same name.
6. Add the file to the recipient's namespace, add the recipient to the access tree, and re-encrypt and save the updated user data.

**Revoking access (`RevokeAccess`)**

1. Verify the caller and their access to the file.
2. Remove the revoked user from the access tree.
3. Generate new random padding and move the file to its new location.
4. Update every remaining user with the new location.

The revoked user is left with stale pointers to a location that no longer holds the file, and no keys to the new one.

---

## Security Properties

| Property              | How it's achieved                                                          |
| --------------------- | -------------------------------------------------------------------------- |
| Confidentiality       | Symmetric encryption for all stored data; public-key encryption for sharing |
| Integrity             | HMACs and digital signatures on stored data and invitations               |
| Authenticity          | Invitations signed by the sender and verified with Keystore keys          |
| Password security     | Argon2 hashing; constant-time HMAC comparison                              |
| Metadata privacy      | Hashed usernames, secret random file IDs, padded storage locations         |
| Revocation            | Re-padding and relocating the file, then updating only authorized users   |

---

## Tech Stack

- **Language:** Go
- **Cryptography:** Argon2, HMAC, public-key encryption, symmetric encryption, digital signatures
- **Storage:** Untrusted key-value Datastore and public Keystore, addressed by UUIDs

---

## Getting Started

```bash
git clone https://github.com/Matt-Hamilton-GitHub/REPO_NAME.git
cd REPO_NAME
go test ./...
```

---

## Authors

- Matt Hamilton
- Dina Khatri
