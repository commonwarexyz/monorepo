//! Finite key distributions for the experimental gamma-6 profile.

use fn_dsa_comm::RngCore;
use zeroize::{Zeroize, Zeroizing};

// floor(2^256 * Pr[|g_i| <= j]), j=0..126, in little-endian limbs.
// The Gaussian variance parameter is 1514017089/2560000, with support [-127,127].
// These thresholds were certified with exact rational exponential enclosures.
const MAGNITUDE_CDF: [[u64; 4]; 127] = [
    [
        0x1a5bbb5896856f55,
        0x1b5328f7f5d4c19b,
        0x430fdd4fd5a60ffd,
        0x043316efc35c763f,
    ],
    [
        0xa32155734b0fe201,
        0xcd3aa797e9e09ba5,
        0x6afb2da1e471a861,
        0x0c9773a42b2e0df2,
    ],
    [
        0x2326eff9794b2bf5,
        0xbf0ab27c0ed47d8a,
        0xcc790f5bb5f93c48,
        0x14f65f32ad6f52bc,
    ],
    [
        0x6f824ee751604a27,
        0x5bafcb87f8955cbb,
        0xf935564b1d106893,
        0x1d4c40add0d81424,
    ],
    [
        0x2bb11f14c9605c05,
        0x6ce149803a7b5dc9,
        0xc7767747cf2cf004,
        0x25958ad806f27717,
    ],
    [
        0x6dfa548f4a50a900,
        0xfa195f3df3bd9874,
        0x35a80cdf65ebfe07,
        0x2dcec0ad1e02b175,
    ],
    [
        0x976c9b00c099e181,
        0x12c91fdd6998477a,
        0x8c159ca39b2ce33f,
        0x35f479c8e07dbf64,
    ],
    [
        0xf543aae9148df552,
        0xfc3c128db6504af5,
        0x72f86ca27f02eba3,
        0x3e0366a1a3bae227,
    ],
    [
        0x705e0a69a6a97d4a,
        0x5d1e689090764030,
        0x5efbceb06b4edc49,
        0x45f8548e0b4548e0,
    ],
    [
        0x4c80001747ad3654,
        0x7460c6a1f7cfab1d,
        0xd01f97aebbc01cc5,
        0x4dd0318de31965d3,
    ],
    [
        0x0879895e1a39ae17,
        0x7618b814a79ee622,
        0xf0bfa0aa4e3bee41,
        0x55880fcea6d50b81,
    ],
    [
        0x669bd6544ae7f6ab,
        0xe1de9b2d0ea2b5af,
        0x1a8b0c24cb0a79c5,
        0x5d1d28e513c92728,
    ],
    [
        0x49b6b536535517d0,
        0xc1cdb9dcad956ecb,
        0x7a3a51aa445a14e6,
        0x648ce0b5fd008bc5,
    ],
    [
        0xa6f5733f7d738c99,
        0x7384d1acaa007116,
        0x3600a6e16d554e81,
        0x6bd4c8097f891207,
    ],
    [
        0xa8a665e0e5242410,
        0x0ee9262d447aa832,
        0xcb3a11abb0031760,
        0x72f29ec4a7498829,
    ],
    [
        0x720cae9f494d8e1f,
        0x145a93876b334a18,
        0x4c0385f04cc821d8,
        0x79e455c68e027dbb,
    ],
    [
        0x038a8181c1b7051a,
        0xc726099cdae493ef,
        0xa16d43ceb588549a,
        0x80a81066fb48bc9d,
    ],
    [
        0xfd81ccff482cca00,
        0xb670c64f7595d3e4,
        0x8e4a736b35042cb1,
        0x873c259589e00e99,
    ],
    [
        0xcc9d6b68e9159652,
        0x298c9d3c02ec1124,
        0xeb3b35dfaf1f44c8,
        0x8d9f209951774b4a,
    ],
    [
        0xf138755d47878bb4,
        0x3d52946e3ebc22f9,
        0x7abda3896c7bfa56,
        0x93cfc172081ee10a,
    ],
    [
        0x8e73d835dc74e170,
        0xda18eb06b6a7c8e0,
        0xc824b3990beb6874,
        0x99ccfcdc79d158ef,
    ],
    [
        0xa9983d9317677742,
        0x7514e2cb187b791a,
        0x887cc91a77f4986a,
        0x9f95fbfd132aea42,
    ],
    [
        0xc3f4fe1faf66c0ed,
        0x039ecf1918655be0,
        0x2ecdb826c2cd6b6d,
        0xa52a1bb40c5ed7d2,
    ],
    [
        0x79e000b2592988ea,
        0x58a23e62d8af2cd1,
        0xca06aace11466972,
        0xaa88eb9f80488d39,
    ],
    [
        0x410c1119b3e2b4e3,
        0xccb28713dc52fced,
        0x0b5a02ea89894e2b,
        0xafb22cd06728f01d,
    ],
    [
        0xbb8e20384a9e2a54,
        0xa4113a69dac100a6,
        0x62e8e801aa573ee7,
        0xb4a5d03803959c33,
    ],
    [
        0xe8e5e6ee756b69c9,
        0x1341f27f17835da3,
        0x05f6494f4c767c3a,
        0xb963f4d3d114f865,
    ],
    [
        0x8660cf3332e7e519,
        0x149047f1e94a4b4c,
        0x6cd44cfad44d0389,
        0xbdece59e6df41e13,
    ],
    [
        0xd6bb0b0ccb7ea1dc,
        0x6934b954755d869b,
        0xd36c70eeacaca1e6,
        0xc241174c4c8f283b,
    ],
    [
        0x8b724ea089aee963,
        0x18e48246ea5ca99b,
        0xa96442b3c083a68c,
        0xc66125db3364bcfc,
    ],
    [
        0xcfe3f6b87d2d51ea,
        0xf8554fba5ca7d3ff,
        0x0e01630934aec322,
        0xca4dd1fbb718a9a0,
    ],
    [
        0x02dd34fb3859d93c,
        0x758f2e5e83602a8b,
        0x1f6f608b59a97fd4,
        0xce07fe5be68bbe72,
    ],
    [
        0x98be10c3c2230713,
        0x4550e85743ea09e1,
        0xc653baa232952349,
        0xd190acda584588d6,
    ],
    [
        0xf79a64961a61fcd2,
        0xf78e397c5d1b3494,
        0xa24e3a27ceb97b39,
        0xd4e8fba8aabce1ee,
    ],
    [
        0xdbbd7d220db84b7f,
        0x66f88a4347be950a,
        0xcbceacf84b398340,
        0xd812226457fd0b9c,
    ],
    [
        0xf6213f5da6101972,
        0x741fdfe9536a3c43,
        0xa62be067079d3797,
        0xdb0d6f2c7a54799e,
    ],
    [
        0x384dfe0ff38f563f,
        0x31fb02adc46e7558,
        0x948bae286175b5b7,
        0xdddc43baccf4b324,
    ],
    [
        0x9f1cc483d83125ef,
        0xd96ed96753a357ab,
        0x18cf58b91461ec27,
        0xe0801285d2a06184,
    ],
    [
        0xe2eb661d096c7ef4,
        0x038cee50bba92db0,
        0x18f262ef554ba9b9,
        0xe2fa5bf19fc021f9,
    ],
    [
        0x61c2e1f5ddce7f5f,
        0xae53e9798cb871e8,
        0x097be5abcec1da2d,
        0xe54cab944e929c92,
    ],
    [
        0x527a9a32c8e399d1,
        0x3b938b6501c4fbc6,
        0xff67eaea448e00dc,
        0xe7789592a5c9a1f0,
    ],
    [
        0xbd3cdd6d9b1fb766,
        0xf7507f2afd8db16f,
        0xa27441dbf7440a7a,
        0xe97fb418f5e29b19,
    ],
    [
        0xe55851c59f6edef4,
        0xb17e1efcc99b9ffa,
        0x1d0f152b8fcc7cd6,
        0xeb63a4f3a9f6bf4a,
    ],
    [
        0xb9e235bdda561d39,
        0x3b0b2ad5aa6f50ae,
        0x8c331fe31a92a1b1,
        0xed26074a7f9e0c82,
    ],
    [
        0xd0bd2b077a5b1c8e,
        0x884b2571da776cbf,
        0x5bc1218f17ebd68e,
        0xeec87980d0b2f940,
    ],
    [
        0x6463e21760c89870,
        0xf3d28aba4aa6c595,
        0x060fde899fcc9673,
        0xf04c973cd30f76e2,
    ],
    [
        0xb7d7bbffab8c3f10,
        0xe113aee2f84a18b9,
        0xc079a55bc614f3f7,
        0xf1b3f7972f5b5021,
    ],
    [
        0xd9d4375e746ceed9,
        0x4053c7b15992b952,
        0xafbddb146da93382,
        0xf3002b73d22b311f,
    ],
    [
        0x84fb1d1ef5b48765,
        0xcb10941dd8d02c4c,
        0x3b96f6e78212a504,
        0xf432bc0463446389,
    ],
    [
        0x62709e8655fae99e,
        0x9d8d731024a130f5,
        0x99f039b5c75a9213,
        0xf54d29745ef1caa1,
    ],
    [
        0xc532f77d21d534f2,
        0xee47b308a031687c,
        0x2b28e027c909c309,
        0xf650e9be65d8be9c,
    ],
    [
        0xb220929331812064,
        0x7bcb405ac38e601f,
        0xb4d5db8773fa65c6,
        0xf73f67a9f95d3b87,
    ],
    [
        0x026a77765d660a5d,
        0x5cb898f3643c0d8e,
        0xbc2bf6fe5b21a49f,
        0xf81a01f085e9b8e2,
    ],
    [
        0x29e7d1643ae03e5b,
        0xd886672288438486,
        0x52ba6cb2dafcbcd6,
        0xf8e20a8851aedb0c,
    ],
    [
        0x8b1aba1fbce1d990,
        0xf09ba51496b1c07b,
        0x27b962d87c1681d5,
        0xf998c613a5d4d78b,
    ],
    [
        0x391286e58bda3bca,
        0x6adfd9fffd7cbb5c,
        0x73d70c86bcfa6128,
        0xfa3f6b7251a56293,
    ],
    [
        0x6610983eeae92f54,
        0xa46ba18482e9e544,
        0x45e8f811b223f381,
        0xfad723737ac4ec21,
    ],
    [
        0xa6944caef0698721,
        0x7b82357a9db165ed,
        0xe009e227945f233d,
        0xfb6108a58ade441b,
    ],
    [
        0x510613e1d57af131,
        0x6713ec7957627de0,
        0xab01a410f19366f9,
        0xfbde2741f1c7b993,
    ],
    [
        0x28963a1e5bc4cc53,
        0x93d3733265dacd43,
        0xd8bd9e0ca1232ba3,
        0xfc4f7d3262a5d140,
    ],
    [
        0x3f67abc011276bb1,
        0x02409ab8c69b1591,
        0x2ca9f1ff70c15c33,
        0xfcb5fa2d2a5189fa,
    ],
    [
        0xfa80c6b263264677,
        0xefb488f36706692b,
        0x6d7be76b3b53ea6b,
        0xfd127fe63ca95235,
    ],
    [
        0x5860dada874340f0,
        0x7fc289a5b5b903c8,
        0xa9c5cd0f14dfce1e,
        0xfd65e2529cc1c321,
    ],
    [
        0xbbdcb8c818fc924a,
        0xb13a3d269247a91c,
        0x18be3c510ba61f57,
        0xfdb0e7fbd06a675e,
    ],
    [
        0x3abc95a6375f5741,
        0xc162a47ed1a45f7c,
        0x3fd37b07164fb291,
        0xfdf44a61216aa199,
    ],
    [
        0xf4b37bd9e58e0659,
        0x67fb6752945a075f,
        0x578866ae59e3fdfc,
        0xfe30b664857905ab,
    ],
    [
        0x3a9692fa235ade20,
        0x73e4338950760134,
        0x4452ec4c781bdc64,
        0xfe66ccc1207bb154,
    ],
    [
        0x678cbbeccbc819c5,
        0xbbae70de123b96a8,
        0xa0c2322f727b7cf6,
        0xfe972289725e9788,
    ],
    [
        0xf4dd141f2662937f,
        0x3bbf07ed5c9b0f2a,
        0x298574ce25af8ff2,
        0xfec241ab62089e0c,
    ],
    [
        0xf752f427409fa25f,
        0xb071e9e291369d14,
        0x32412cee5ae1e753,
        0xfee8a97879069260,
    ],
    [
        0x5e503f96b908d506,
        0xf4cac5384c61d536,
        0xe14fdbe1f9f7af05,
        0xff0acf30c6c325a2,
    ],
    [
        0x08dcfa3f8ea55161,
        0x10b6de9289600af3,
        0x6a94a506e70f67b4,
        0xff291e8f06019bfe,
    ],
    [
        0x86a2541049590a48,
        0x386e17c23a22e109,
        0x67962e34eeba44f5,
        0xff43fa54c347802a,
    ],
    [
        0xde64d905440769f8,
        0x52cc64987f8dc984,
        0x1eab69cdb4d095db,
        0xff5bbcd566788045,
    ],
    [
        0x771c3bbd4b50a23f,
        0x875cfe21e61f8644,
        0xa877a1e47bfe793d,
        0xff70b87f24b53a17,
    ],
    [
        0x210bb8489bff1e61,
        0x9dae75c297335bd8,
        0x6daace4c8fbc4f8e,
        0xff83386101376645,
    ],
    [
        0x03fc745a52025b4d,
        0xe95e64372ad833e2,
        0xafd0f0db3ee49d1b,
        0xff9380ad241f2ef2,
    ],
    [
        0x59cedd7472e152ac,
        0x3b5c30bc63a0d529,
        0xed1bd8af9f6a973b,
        0xffa1cf36ecb03aa9,
    ],
    [
        0x9d3d45f56553b60d,
        0x4e895d4a44ac2ac1,
        0x0772359c0ffc0f67,
        0xffae5bec41281c0c,
    ],
    [
        0x38e54eb980a6b53b,
        0xd83898133ca933c4,
        0x81e8bb44942945b3,
        0xffb95949b8ff0e37,
    ],
    [
        0x961f881a516c2f0b,
        0x0de49a195214a36c,
        0xb25915e0f30e59c6,
        0xffc2f4c956ee7f07,
    ],
    [
        0xf76e1014cacf0c2f,
        0x1f20d20d0368e028,
        0x63701624f469001f,
        0xffcb574b9e78e1cd,
    ],
    [
        0x37f4fdde823b88dc,
        0x15122ab77d92b501,
        0xa379a06b7766b5b2,
        0xffd2a57ae4df3747,
    ],
    [
        0xb2f6106c06ac241b,
        0x10f2d3c04d45f0de,
        0x456dc87c87817000,
        0xffd90028cf76b8fe,
    ],
    [
        0xf8675ed277f198bd,
        0xa2ae75689ffbd11f,
        0xf383be6c9d7837c6,
        0xffde84a601379d0b,
    ],
    [
        0x9d17d57c71566928,
        0x053a10bb5a775f72,
        0x126b53f4bf33d905,
        0xffe34d140736ae9d,
    ],
    [
        0x18aab04e1a8070ba,
        0x5233cd5c094c196c,
        0x54e2bdc048ceeff0,
        0xffe770b19f9d6a90,
    ],
    [
        0x3df3637aa89af863,
        0xc513aa9b436e5f24,
        0x82e7b1604033b348,
        0xffeb042180ba840a,
    ],
    [
        0xd5133c3c5c5bfbd6,
        0x6e72e0344fd15eb7,
        0x85b88258df93d7b4,
        0xffee19abce0d71b6,
    ],
    [
        0x2b6a65d6b6ddeada,
        0xfbedbb47537ed5ac,
        0xdc4cbc75062373fd,
        0xfff0c17a6fdb7da1,
    ],
    [
        0x116011d657e3c668,
        0x42b1d31398bb4709,
        0x0cf8d023b812ebfb,
        0xfff309d0870dd637,
    ],
    [
        0x6650a6341fe687ab,
        0xfc3346d16d03fd3c,
        0x7e6264e223d17627,
        0xfff4ff3d3af11d31,
    ],
    [
        0x45a826913f206768,
        0xa34d179ea6327f23,
        0x1783276d7f3cd874,
        0xfff6acca2112d194,
    ],
    [
        0x1f89ed87e8e6cff7,
        0xc6301445c9fedb43,
        0xff2eef0e4875bc27,
        0xfff81c25810a25c5,
    ],
    [
        0xbb56a1ecabbff6ff,
        0x04de2914e9da6356,
        0x954a95b0f99733f8,
        0xfff955c8b699dd6b,
    ],
    [
        0x3bdfbd878983c0ea,
        0x8ab3a1cc23d4d9e8,
        0xe4298e4b039cc50d,
        0xfffa611af467dd82,
    ],
    [
        0xd271ad4fab669bff,
        0xac6fecc29657430b,
        0x974ce83cf1050d4c,
        0xfffb4490a8a3b605,
    ],
    [
        0x55f2c789a03cb490,
        0x69af77919643e6e1,
        0xe2a7dde0d3bb82c7,
        0xfffc05c7c37c3d69,
    ],
    [
        0x08a849905f77fe7b,
        0x4f729d09e4dbf3b4,
        0x8b407a5b59fb9657,
        0xfffca9a11d4ff2fc,
    ],
    [
        0x06b4fcce590eafcb,
        0xd7e97969e7788cd6,
        0xf70b0cfee7548cc9,
        0xfffd3457382cafdb,
    ],
    [
        0x61481a5d2b2544f6,
        0xdd7bf9d598b129c4,
        0xcbf6fbecaf298e67,
        0xfffda992958f661e,
    ],
    [
        0xcbded4d8c7aae7f3,
        0x97cab4eeed14851a,
        0x456ed4b12bd628a6,
        0xfffe0c7bd6783a13,
    ],
    [
        0xd5d819b1f2c26338,
        0xd6e6c4db4e72e68e,
        0x48533210445ef2d5,
        0xfffe5fcbd8e3da28,
    ],
    [
        0x0a8a583fd9349ab7,
        0xb0067b0011b633cc,
        0x2f973130a2d69259,
        0xfffea5da02a02e46,
    ],
    [
        0x67a46668f4c8b193,
        0xa3eb0fa4f360dff8,
        0x55e16c10070ca95b,
        0xfffee0a8e64dc4e4,
    ],
    [
        0x706839020dd4e8c7,
        0xf8d7ef4b5cc5665d,
        0x20d85c648d1e0ca1,
        0xffff11f16c3c5380,
    ],
    [
        0x1620cf02e4d4701f,
        0x62851c9e5bac91b0,
        0x0c8c99861af96d05,
        0xffff3b2ca5b8e4f3,
    ],
    [
        0x11d2c465f9cafba2,
        0xef77d0ecc313adcf,
        0x141a498f69eae6c3,
        0xffff5d9c6e5fecbc,
    ],
    [
        0xf246e67e31e39d77,
        0xe568fe6118f3fde8,
        0x2ab8612fd8b0d648,
        0xffff7a52fc1ae095,
    ],
    [
        0x637567e70d36e2bd,
        0x0ac7eed2abe3410d,
        0xaa93f343c9494f57,
        0xffff92397ba54136,
    ],
    [
        0x521ee0da9f8d8bd8,
        0x8b1e35e317de32aa,
        0xfe78e0a9338209d1,
        0xffffa615d4cbef28,
    ],
    [
        0x7e4ec29861ac974c,
        0x36033df150caf540,
        0x29282d50dd018645,
        0xffffb68faf15fcfa,
    ],
    [
        0x6c44e6a06312c18e,
        0xb91acfc514b2668b,
        0x588bd07e5c35e230,
        0xffffc434cd29a1da,
    ],
    [
        0x6dcb74e012bde424,
        0xa285ed23e14bac80,
        0x58101ed2c372cb14,
        0xffffcf7cd30b6638,
    ],
    [
        0x1bd7a71bcd6cbcf4,
        0x805f6778bcc8701d,
        0x42f7525f18235b3a,
        0xffffd8cc8949522c,
    ],
    [
        0x91ec4e3f15d19217,
        0x85f62f3cf060db24,
        0x80e38d1d61101fcd,
        0xffffe078ad3f66d8,
    ],
    [
        0x0048384ec268b2d7,
        0xae0a00ee25bdf184,
        0x5663878b2095cb50,
        0xffffe6c85ce51fff,
    ],
    [
        0xb02f08eb10eef9dc,
        0x4d1bbe74b7661125,
        0xae70223d3cc74efd,
        0xffffebf72afbde41,
    ],
    [
        0xa07d8ab7c8e7b5c3,
        0xee983308c86e787d,
        0x91035087f4adbb2f,
        0xfffff036e7025c22,
    ],
    [
        0x079649cc6edc6dc9,
        0xb3376a4c613ee01b,
        0xf22ec663431ffd72,
        0xfffff3b122ffe5d5,
    ],
    [
        0x9b630f41174e58c8,
        0x2b8f31ba7d49d6c7,
        0xb763dd308e442364,
        0xfffff68880090389,
    ],
    [
        0x7a6fa6fdb49eceb4,
        0x0175281351177dd3,
        0x7ea3dc8fd1cec6e9,
        0xfffff8d9c94c9323,
    ],
    [
        0xaf4b836b024036a2,
        0x99be4a343071e178,
        0x963741e1188a2e1f,
        0xfffffabce481d847,
    ],
    [
        0xa3d0abdee460744b,
        0x24f52d79b5c68714,
        0x41cb03217822a52f,
        0xfffffc459db3b461,
    ],
    [
        0xd030e0d6dc407fd2,
        0x55351c09666373e3,
        0xa7cb118b77a95ba3,
        0xfffffd8453a0ef0d,
    ],
    [
        0xb348292950c53eb8,
        0x1de1c6f6b69e0aab,
        0x494c886f9e101cdf,
        0xfffffe86893b31b5,
    ],
    [
        0x5a61ed08dbf2fac8,
        0x61bbdf8e35c3a5a7,
        0xab3108ec9cd1a49d,
        0xffffff5760342205,
    ],
];

// Each trial consumes two bytes, interpreted as a little-endian u16. The
// rejected suffix depends only on the public range, never on the remaining weight.
fn uniform_below<R: RngCore>(rng: &mut R, range: u32) -> u32 {
    let limit = 65536 - 65536 % range;
    let reciprocal = (1u64 << 32) / u64::from(range);
    let mut bytes = Zeroizing::new([0u8; 2]);
    loop {
        rng.fill_bytes(&mut *bytes);
        let value = u32::from(u16::from_le_bytes(*bytes));
        if value < limit {
            // With value < 2^16, the public reciprocal underestimates the
            // quotient by at most one. One masked subtraction completes it.
            let quotient = ((u64::from(value) * reciprocal) >> 32) as u32;
            let remainder = value - quotient * range;
            let reduced = remainder.wrapping_sub(range);
            return reduced.wrapping_add(range & 0u32.wrapping_sub(reduced >> 31));
        }
    }
}

/// Sample a uniform ternary polynomial of weight 233 with independent signs.
///
/// Each position consumes a uniform range draw followed by one sign byte,
/// including positions where the support choice is forced. Only its low bit is used.
pub(super) fn sample_f<R: RngCore>(rng: &mut R) -> [i8; 512] {
    let mut result = [0i8; 512];
    let mut remaining = 233u32;
    let mut sign = Zeroizing::new([0u8; 1]);
    for (i, coefficient) in result.iter_mut().enumerate() {
        let value = uniform_below(rng, (512 - i) as u32);
        let selected = value.wrapping_sub(remaining) >> 31;
        remaining -= selected;
        rng.fill_bytes(&mut *sign);
        *coefficient = (selected as i8) * (1 - 2 * (sign[0] & 1) as i8);
    }
    result
}

// Every threshold and every limb is visited, regardless of the sampled value.
// Each widened limb difference is in [-2^64,2^64-1], so its top bit is the borrow.
fn magnitude(value: &[u64; 4]) -> u8 {
    let mut result = 0;
    for threshold in &MAGNITUDE_CDF {
        let mut borrow = 0u128;
        for i in 0..4 {
            let difference = (value[i] as u128).wrapping_sub(threshold[i] as u128 + borrow);
            borrow = difference >> 127;
        }
        result += (borrow as u8) ^ 1;
    }
    result
}

/// Sample the quantized finite Gaussian, conditioned on odd polynomial parity.
///
/// Each coefficient consumes 32 little-endian magnitude bytes followed by one
/// sign byte (low bit only). Even-parity candidates are discarded in their entirety.
pub(super) fn sample_g<R: RngCore>(rng: &mut R) -> [i8; 512] {
    let mut bytes = Zeroizing::new([0u8; 33]);
    let mut value = Zeroizing::new([0u64; 4]);
    let mut result = [0i8; 512];
    loop {
        let mut parity = 0u8;
        for coefficient in &mut result {
            rng.fill_bytes(&mut bytes[..32]);
            for (limb, encoded) in value.iter_mut().zip(bytes[..32].as_chunks::<8>().0) {
                *limb = u64::from_le_bytes(*encoded);
            }
            let absolute = magnitude(&value);
            rng.fill_bytes(&mut bytes[32..]);
            *coefficient = (absolute as i8) * (1 - 2 * (bytes[32] & 1) as i8);
            parity ^= absolute;
        }
        if parity & 1 == 1 {
            return result;
        }
        result.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    struct ScriptedRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl ScriptedRng {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl RngCore for ScriptedRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.offset + dest.len();
            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fn_dsa_comm::RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn append_coefficient(bytes: &mut Vec<u8>, value: [u64; 4], sign: u8) {
        for limb in value {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        bytes.push(sign);
    }

    #[test]
    fn cdf_boundaries_and_extrema() {
        assert_eq!(magnitude(&[0; 4]), 0);
        assert_eq!(magnitude(&[u64::MAX; 4]), 127);
        for (i, threshold) in MAGNITUDE_CDF.iter().enumerate() {
            let mut below = *threshold;
            for limb in &mut below {
                let (difference, borrow) = limb.overflowing_sub(1);
                *limb = difference;
                if !borrow {
                    break;
                }
            }
            assert_eq!(magnitude(&below), i as u8);
            assert_eq!(magnitude(threshold), i as u8 + 1);
        }
    }

    #[test]
    fn cdf_limb_borrows() {
        for i in 1..4 {
            for threshold in MAGNITUDE_CDF {
                let mut value = threshold;
                value[..i].fill(0);
                let expected = MAGNITUDE_CDF
                    .iter()
                    .filter(|t| t.iter().rev().cmp(value.iter().rev()).is_le())
                    .count() as u8;
                assert_eq!(magnitude(&value), expected);
                value[..i].fill(u64::MAX);
                let expected = MAGNITUDE_CDF
                    .iter()
                    .filter(|t| t.iter().rev().cmp(value.iter().rev()).is_le())
                    .count() as u8;
                assert_eq!(magnitude(&value), expected);
            }
        }
    }

    #[test]
    fn uniform_range_rejects_incomplete_suffix() {
        let mut rng = ScriptedRng::new(
            [65535u16, 65408, 65407]
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect(),
        );
        assert_eq!(uniform_below(&mut rng, 511), 510);
        assert_eq!(rng.offset, 6);
    }

    #[test]
    fn uniform_range_has_equal_preimage_counts() {
        for range in [1u32, 2, 3, 7, 233, 255, 511, 512] {
            let limit = 65536 - 65536 % range;
            let bytes = (0..limit).flat_map(|x| (x as u16).to_le_bytes()).collect();
            let mut rng = ScriptedRng::new(bytes);
            let mut counts = [0u32; 512];
            for _ in 0..limit {
                counts[uniform_below(&mut rng, range) as usize] += 1;
            }
            assert!(counts[..range as usize].iter().all(|&x| x == limit / range));
            assert_eq!(rng.offset, 2 * limit as usize);
        }
    }

    #[test]
    fn fixed_weight_support_and_signs() {
        for sign in [0u8, 1, 2, 3, 254, 255] {
            let bytes = (0..512).flat_map(|_| [0, 0, sign]).collect();
            let mut rng = ScriptedRng::new(bytes);
            let f = sample_f(&mut rng);
            assert_eq!(f.iter().filter(|&&x| x != 0).count(), 233);
            assert_eq!(f.iter().map(|&x| i32::from(x)).sum::<i32>() & 1, 1);
            assert!(f[..233].iter().all(|&x| x == 1 - 2 * (sign & 1) as i8));
            assert!(f[233..].iter().all(|&x| x == 0));
            assert_eq!(rng.offset, 3 * 512);
        }
    }

    #[test]
    fn support_selection_is_uniform_in_a_four_position_suffix() {
        let mut counts = [0u32; 16];
        for a in 0u16..4 {
            for b in 0u16..3 {
                for c in 0u16..2 {
                    let mut bytes = Vec::new();
                    for i in 0..508 {
                        let value = if i < 231 { 0u16 } else { 2 };
                        bytes.extend_from_slice(&value.to_le_bytes());
                        bytes.push(0);
                    }
                    for value in [a, b, c, 0] {
                        bytes.extend_from_slice(&value.to_le_bytes());
                        bytes.push(0);
                    }
                    let mut rng = ScriptedRng::new(bytes);
                    let f = sample_f(&mut rng);
                    assert_eq!(f.iter().filter(|&&x| x != 0).count(), 233);
                    let mask = f[508..]
                        .iter()
                        .enumerate()
                        .fold(0, |mask, (i, &x)| mask | ((x != 0) as usize) << i);
                    counts[mask] += 1;
                }
            }
        }
        for (mask, count) in counts.into_iter().enumerate() {
            assert_eq!(count, if mask.count_ones() == 2 { 4 } else { 0 });
        }
    }

    #[test]
    fn gaussian_rejects_the_whole_even_polynomial() {
        let mut bytes = Vec::new();
        for _ in 0..512 {
            append_coefficient(&mut bytes, MAGNITUDE_CDF[1], 0);
        }
        append_coefficient(&mut bytes, MAGNITUDE_CDF[0], 1);
        for _ in 1..512 {
            append_coefficient(&mut bytes, [0; 4], 0);
        }
        let mut rng = ScriptedRng::new(bytes);
        let g = sample_g(&mut rng);
        assert_eq!(g[0], -1);
        assert!(g[1..].iter().all(|&x| x == 0));
        assert_eq!(rng.offset, 2 * 512 * 33);
    }

    #[test]
    fn gaussian_sign_and_extreme_support() {
        for sign in [0u8, 1, 2, 3, 254, 255] {
            let mut bytes = Vec::new();
            append_coefficient(&mut bytes, [u64::MAX; 4], sign);
            for _ in 1..512 {
                append_coefficient(&mut bytes, [0; 4], sign);
            }
            let mut rng = ScriptedRng::new(bytes);
            let g = sample_g(&mut rng);
            assert_eq!(g[0], 127 * (1 - 2 * (sign & 1) as i8));
            assert!(g[1..].iter().all(|&x| x == 0));
            assert_eq!(rng.offset, 512 * 33);
        }
    }
}
