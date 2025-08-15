# Sign-In with Ethereum PHP
This package provides a PHP implementation of EIP-4361: Sign In With Ethereum.

## Installation
```shell
composer require lz/siwe
```
## Usage
1. The wallet is connected to the client, then the wallet address is sent to the server 
2. On the server we generate SIWE messages.
```php
$params = new SiweMessageParams(
    address: $address,
    chainId: 1,
    domain: "example.com",
    uri: "https://example.com/path"
);
```
or with params builder:
```php
$params = SiweMessageParamsBuilder::create()
            ->withAddress($address)
            ->withChainId(1)
            ->withDomain("example.com")
            ->withUri("https://example.com/path")->build();
```
And we generate the message text:
```php
$message = SiweMessage::create($params);
```
3. On the client side, we sign the SIWE message via personal_sign. We send the received signature to the server.
4. All that remains is to check the signature.
```php
if (SiweMessage::verify($params, $signature)) {
    // authorization success
} else {
    // authorization failed (signature invalid)
}
```
You can also look at a fully working [example](example) of authorization using the library.

## Links
- [EIP-4361 Specification](https://eips.ethereum.org/EIPS/eip-4361).
- [Example of use](example)