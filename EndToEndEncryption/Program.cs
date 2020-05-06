using System;
using System.Linq;

namespace EndToEndEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            User alice = new User();
            User bob = new User();

            alice.GenerateVerifiedSharedKey(bob.PublicKey, bob.SignedPublicKey, bob.RSAPublicKey);
            bob.GenerateVerifiedSharedKey(alice.PublicKey, alice.SignedPublicKey, alice.RSAPublicKey);
        }

    }
}
