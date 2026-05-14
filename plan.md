Make an end-to-end encrypted, local-first, vanilla js secret sharing PWA.

It is intended for small text and files, either a single text input or a
single file upload, whatever the user selects.

The problem with existing solutions like wormhole or send is that they start
with the person wanting to share a file, and you end up with a link that anyone
can use to decrypt the file. So you're protected against the server, but it's
still not safe to send the link over an unsafe channel.

I want to invert the process and start with the person who wants to receive
the file.

When the app launches, it should generate a key pair if one doesn't already
exist in local storage.

To protect against an attacker swapping in their own public key, an emoji
fingerprint should also be displayed, so the receiver can communicate it over
a second channel.

The app should then display a URL like this:

`https://example.com?k=<public key>`

The emoji fingerprint should be displayed here as well. Actually using the
fingerprint is up to the users. Don't make the UX worse by trying to force
compliance.

When someone else loads that URL, it should display a page with a text input
box and a "Generate Link" button.

There should also be a button to upload a file, but since the final base64
has to fit in a URL, warn them if it's likely to big.

When they click the button, it should use the public key from the URL to
encrypt whatever is in the box, convert it to base64, and generate a new link
like this:

`https://example.com?k=<public key>&d=<base64 of encrypted data>`

They can then send that link back to the original person, and when they open
it the data is decrypted and displayed.

Keep everything simple and minimal, including JS, HTML, and CSS. We can always
make it more fancy later.
