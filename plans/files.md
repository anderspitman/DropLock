Let's start working on adding support for files. I want to define a simple
binary file format for encrypted messages. It should have a magic number and
format version at the beginning. It should also be able to encode the public
key that was used to encrypt the data, and whatever other metadata is
necessary.

For binary files that are too big to fit in the URL this format can be attached
to emails/slack messages/etc. For files that are small enough to fit in a URL,
it will be base64url encoded directly. Let's use #m=<message>
