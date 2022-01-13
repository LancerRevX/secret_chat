class SecretChatError(RuntimeError): pass


class InvalidPackageError(SecretChatError): pass


class PackageEncryptedError(SecretChatError): pass


class InvalidRequestError(SecretChatError): pass


class ClientDisconnectedError(SecretChatError): pass