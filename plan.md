Make DropLock, an end-to-end encrypted, vanilla JS secret sharing web app.

It is intended for small text secrets.

The problem with existing solutions like wormhole or send is that they start
with the person wanting to share a secret, and you end up with a link that
anyone can use to decrypt it. So you're protected against the server, but it's
still not safe to send the link over an unsafe channel.

I want to invert the process and start with the person who wants to receive
the secret.

When the app launches, it should generate a non-extractable key pair if one
doesn't already exist in IndexedDB.

To protect against an attacker swapping in their own public key, a 16 emoji
fingerprint should also be displayed, so the receiver can communicate it over
a second channel.

The app should then display a URL like this:

`https://example.com/#k=<public key>`

The emoji fingerprint should be displayed here as well. Actually using the
fingerprint is up to the users. Don't make the UX worse by trying to force
compliance.

When someone else loads that URL, it should display a page with a text input
box and a "Generate Link" button.

It should also tell the sender to make sure the emojis match what the recipient
sent through another communication channel.

When they click the button, it should use the public key from the URL fragment
to encrypt whatever is in the box, convert it to base64, and generate a new
link like this:

`https://example.com/#k=<public key>&d=<base64 of encrypted data>`

They can then send that link back to the original person, and when they open
it the data is decrypted and displayed.

Keep everything simple and minimal, including JS, HTML, and CSS. We can always
make it more fancy later.
