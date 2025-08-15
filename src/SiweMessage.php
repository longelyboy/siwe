<?php
declare(strict_types=1);

namespace Zbkm\Siwe;

use Exception;
use Zbkm\Siwe\Ethereum\Signature;
use Zbkm\Siwe\Exception\SignatureException;
use Zbkm\Siwe\Exception\SiweTimeException;
use Zbkm\Siwe\Utils\TimeFormatter;
use Zbkm\Siwe\Validators\SiweMessageTimeValidator;

class SiweMessage
{
    /**
     * Create SIWE message.
     *
     * @param SiweMessageParams $params
     * @return string
     */
    public static function create(SiweMessageParams $params): string
    {
        $domain = $params->scheme ? $params->scheme . "://" . $params->domain : $params->domain;

        $message = $domain . " wants you to sign in with your Ethereum account:\n" . $params->address . "\n\n";

        if ($params->statement) {
            $message .= $params->statement . "\n";
        }

        $message .= "\nURI: " . $params->uri . "\n";
        $message .= "Version: " . $params->version . "\n";
        $message .= "Chain ID: " . $params->chainId . "\n";
        $message .= "Nonce: " . $params->nonce . "\n";
        $message .= "Issued At: " . TimeFormatter::datetimeToISO($params->issuedAt);

        if ($params->expirationTime) {
            $message .= "\nExpiration Time: " . TimeFormatter::datetimeToISO($params->expirationTime);
        }

        if ($params->notBefore) {
            $message .= "\nNot Before: " . TimeFormatter::datetimeToISO($params->notBefore);
        }

        if ($params->requestId) {
            $message .= "\nRequest ID: " . $params->requestId;
        }

        if ($params->resources) {
            $message .= "\nResources:";
            foreach ($params->resources as $resource) {
                $message .= "\n- " . $resource;
            }
        }

        return $message;
    }

    /**
     * Parse SIWE message to params format
     *
     * @param string $message
     * @return SiweMessageParams
     */
    public static function parse(string $message): SiweMessageParams
    {
        // regex from https://github.com/wevm/viem/blob/main/src/utils/siwe/parseSiweMessage.ts
        $re = '/^
(?P<domain>[a-zA-Z0-9\-.]+(?::\d{1,5})?)\s+wants\s+you\s+to\s+sign\s+in\s+with\s+your\s+Ethereum\s+account:\R
(?P<address>0x[a-fA-F0-9]{40})\R
(?:([^\R]+)\R)?                           # 可选声明
URI:\s+(?P<uri>\S+)\R
Version:\s+(?P<version>\S+)\R
Chain\s+ID:\s+(?P<chainId>\d+)\R
Nonce:\s+(?P<nonce>[a-fA-F0-9]+)\R
Issued\s+At:\s+(?P<issuedAt>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)
(?:\RExpiration\s+Time:\s+(?P<expirationTime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z))?
(?:\RNot\s+Before:\s+(?P<notBefore>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z))?
(?:\RRequest\s+ID:\s+(?P<requestId>[^\R]+))?
$/msx';

        preg_match($re, $message, $params);
        $params["chainId"] = (int)$params["chainId"];
        $params = array_filter($params, function($value) {
            return $value !== '';
        });

        if (array_key_exists("expirationTime", $params)) {
            $params["expirationTime"] = TimeFormatter::ISOToDatetime($params["expirationTime"]);
        }

        if (array_key_exists("issuedAt", $params)) {
            $params["issuedAt"] = TimeFormatter::ISOToDatetime($params["issuedAt"]);
        }

        if (array_key_exists("notBefore", $params)) {
            $params["notBefore"] = TimeFormatter::ISOToDatetime($params["notBefore"]);
        }

        $resources = explode("Resources:\n", $message);

        if (isset($resources[1])) {
            $params["resources"] = array_map(function ($r) {
                return substr($r, 2);
            }, explode("\n", trim($resources[1])));
        }

        return SiweMessageParams::fromArray($params);
    }

    /**
     * Verify signature for SIWE in params format
     *
     * @param SiweMessageParams $params
     * @param string $signature
     * @return bool
     */
    public static function verify(SiweMessageParams $params, string $signature): bool
    {
        try {
            self::verifyOrFail($params, self::create($params), $signature);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Verify signature for SIWE message
     *
     * @param string $message
     * @param string $signature
     * @return bool
     */
    public static function verifyMessage(string $message, string $signature): bool
    {
        try {
            self::verifyOrFail(self::parse($message), $message, $signature);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Verify signature or except
     *
     * @param SiweMessageParams $params
     * @param string $message
     * @param string $signature
     * @return bool
     * @throws SignatureException|SiweTimeException
     */
    public static function verifyOrFail(SiweMessageParams $params, string $message, string $signature): bool
    {
        SiweMessageTimeValidator::validateOrFail($params);
        if (Signature::verifyMessage($message, $signature, $params->address)) {
            return true;
        }

        throw new SignatureException("Signature invalid");
    }
}