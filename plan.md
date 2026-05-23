Make DropLock, an end-to-end encrypted, vanilla JS secret sharing web app.

It is intended for text secrets and single-file secrets.

The problem with existing solutions like wormhole or send is that they start
with the person wanting to share a secret, and you end up with a link that
anyone can use to decrypt it. So you're protected against the server, but it's
still not safe to send the link over an unsafe channel.

I want to invert the process and start with the person who wants to receive
the secret.

When the app launches, it should generate a non-extractable key pair if one
doesn't already exist in IndexedDB. The user can generate a new key after a
warning that old messages for the current key will no longer decrypt.

To protect against an attacker swapping in their own public key, a 16 emoji
fingerprint should also be displayed, so the receiver can communicate it over
a second channel.

The app should then display a URL like this:

`https://example.com/#k=<public key>`

The emoji fingerprint should be displayed here as well. Actually using the
fingerprint is up to the users. Don't make the UX worse by trying to force
compliance.

When someone else loads that URL, it should display a page with a text input,
a file input, and a "Generate Link" button.

It should also tell the sender to make sure the emojis match what the recipient
sent through another communication channel.

When they click the button, it should use the public key from the URL fragment
to encrypt the selected text or file into the DropLock binary message format.
If the message is small enough, generate a link like this:

`https://example.com/#m=<base64 of encrypted message>`

Also generate a `.droplock` file that can be sent back instead of a link.
When the original person opens the link or file, the data is decrypted and
displayed or downloaded.

Keep everything simple and minimal, including JS, HTML, and CSS. We can always
make it more fancy later.
