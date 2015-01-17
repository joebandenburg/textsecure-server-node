An independent JavaScript implementation of a TextSecure server.

Currently, this server is not complete and should not be used for anything other than testing. If you're looking for a
production server to run, you should check out the
[official TextSecure server](https://github.com/WhisperSystems/TextSecure-Server) instead. The project aims to
eventually implement the complete functionality of the official TextSecure server.

The server is structured as a library so that it can be used in a variety of different applications. Currently it is
used by the integration tests of [libtextsecure-javascript](https://github.com/joebandenburg/libtextsecure-javascript).

The official TextSecure server has lots of external dependencies (database, S3, SMS sending platform), whereas this
project aims to make those dependencies optional and provide internal alternatives where possible. This should make the
setup process very easy.
