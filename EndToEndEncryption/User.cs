using System;
using System.Collections.Generic;
using System.Data;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace EndToEndEncryption
{
    class User
    {

        public ECDiffieHellmanPublicKey PublicKey { get; private set; }

        public byte[] SignedPublicKey { get; private set; }

        public RSAParameters RSAPublicKey { get; private set; }

        private readonly ECDiffieHellman DiffieHellman;

        private readonly RSA RSAKeyExchange;

        private byte[] SharedKey;

        public User()
        {
            RSAKeyExchange = RSA.Create();
            RSAPublicKey = RSAKeyExchange.ExportParameters(false);
            DiffieHellman = ECDiffieHellman.Create();
            PublicKey = DiffieHellman.PublicKey;
            SignedPublicKey = RSAKeyExchange.SignData(PublicKey.ToByteArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Computes a hash using the users private RSA key.
        /// </summary>
        public byte[] SignData(byte[] data)
        {
            return RSAKeyExchange.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Generates a shared verified key.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="signedPublicKey"></param>
        /// <param name="parameters"></param>
        public void GenerateVerifiedSharedKey(ECDiffieHellmanPublicKey publicKey, byte[] signedPublicKey, RSAParameters parameters)
        {
            if (VerifySignedData(publicKey.ToByteArray(), signedPublicKey, parameters))
            {
                GenerateSharedKey(publicKey);
            }
            else
            {
                Console.WriteLine("Could not create end-to-end encryption key. RSA signing does not match.");
            }
        }

        /// <summary>
        /// Generates a key shared between users for AES end-to-end encryption.
        /// </summary>
        /// <param name="publicKey"></param>
        private void GenerateSharedKey(ECDiffieHellmanPublicKey publicKey)
        {
            SharedKey = DiffieHellman.DeriveKeyMaterial(publicKey);
        }

        /// <summary>
        /// Verifies data using users RSA public key.
        /// </summary>
        public bool VerifySignedData(byte[] data, byte[] signature, RSAParameters parameters)
        {
            using (RSA rsa = RSA.Create(parameters))
            {
                bool verified = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return verified;
            }
        }
    }
}