﻿//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace System.IdentityModel.Test
{
    static public class KeyingMaterial
    {
        static KeyingMaterial()
        {
            byte[] cspbytes_1024 = Base64UrlEncoder.DecodeBytes("BwIAAACkAABSU0EyAAQAAAEAAQAlur35vBYFooH0yfB3G919joyz-7xD8LcoQLRIqV7DdEicgTkJWD8sfDvxHRf18w2bA2kx_Bg89855uR3yDvIqtcZ-vq6Gv6yvx7iSjuXW_SNV4gVSjShBuCMelyU-dsHK-IuLcyMcms93fQ3Gh13_AFeyGuT2P0g7LUEEdz8K099x6CCApMROhY261NbN-d5uDE33bypd8tfLCWj2jlSZUNX__O7OUCVqegyI3rAPCpbtB5V7jw7uKD2lR6OeZfN7fPlPPtQEXyaIzYQHo8td6ASYcIFAUjxkBhN8lMUG2FXe-jH3tYYf3FMywf6GA6bo1LfVMW1Sb935YrGAt_fd-8YFoKDUoZgMTjcEiM0Koq80DM8Hy0rb1F4KnzKpXPy2XeGAxIEM-6MMINuh2aY-gZ6oMUomEcw9uSW1hBNk5mtPAdUqHfud8RBYvTH5yx-Cipu6wDLoQl4UTZcop-tVLpJGWJpDYkeLsda2pKJpJcITs3_gRq-QjUIG7-M2OMEvKwBd3tMfIHNkVA-RBk6v_dEHH8cRHvPZC2wna7FQztJqN5ybOSWcpqCX5RvbMkfK38hdGo6oPUkQ3YmtFLFOialpsJo-c_HDOlI32fCnjTLRsR9B-JbSDRLEHg0bVmgVyL1oZaLPYAMyUH6grtel2enOiUODgX9YZbynGtHjvGMn0-3nbz2TRUlchl5b-mQqPbM673WnddAUeaaqNc7gopo5Zofsd6-YV1Z0nL-XzLad2Ax9aAHpVoejevXGz1w");
            byte[] cspbytes_1024_Public = Base64UrlEncoder.DecodeBytes("BgIAAACkAABSU0ExAAQAAAEAAQAlur35vBYFooH0yfB3G919joyz-7xD8LcoQLRIqV7DdEicgTkJWD8sfDvxHRf18w2bA2kx_Bg89855uR3yDvIqtcZ-vq6Gv6yvx7iSjuXW_SNV4gVSjShBuCMelyU-dsHK-IuLcyMcms93fQ3Gh13_AFeyGuT2P0g7LUEEdz8K0w");

            RsaParameters_1024 =
                new RSAParameters
                {
                    D = Base64UrlEncoder.DecodeBytes("XM_G9Xqjh1bpAWh9DNidtsyXv5x0VleYr3fsh2Y5mqLgzjWqpnkU0HWnde86sz0qZPpbXoZcSUWTPW_n7dMnY7zj0RqnvGVYf4GDQ4nO6dml166gflAyA2DPomVovcgVaFYbDR7EEg3SlvhBH7HRMo2n8Nk3UjrD8XM-mrBpqYk"),
                    DP = Base64UrlEncoder.DecodeBytes("5mQThLUluT3MESZKMaiegT6m2aHbIAyj-wyBxIDhXbb8XKkynwpe1NtKywfPDDSvogrNiAQ3TgyYodSgoAXG-w"),
                    DQ = Base64UrlEncoder.DecodeBytes("wTg24-8GQo2Qr0bgf7MTwiVpoqS21rGLR2JDmlhGki5V66col00UXkLoMsC6m4qCH8v5Mb1YEPGd-x0q1QFPaw"),
                    Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                    InverseQ = Base64UrlEncoder.DecodeBytes("TrEUrYndEEk9qI4aXcjfykcy2xvll6CmnCU5m5w3atLOULFrJ2wL2fMeEccfB9H9r04GkQ9UZHMgH9PeXQArLw"),
                    Modulus = Base64UrlEncoder.DecodeBytes("0wo_dwRBLTtIP_bkGrJXAP9dh8YNfXfPmhwjc4uL-MrBdj4llx4juEEojVIF4lUj_dbljpK4x6-sv4auvn7GtSryDvIduXnO9zwY_DFpA5sN8_UXHfE7fCw_WAk5gZxIdMNeqUi0QCi38EO8-7OMjn3dG3fwyfSBogUWvPm9uiU"),
                    P = Base64UrlEncoder.DecodeBytes("82Weo0elPSjuDo97lQftlgoPsN6IDHpqJVDO7vz_1VCZVI72aAnL1_JdKm_3TQxu3vnN1tS6jYVOxKSAIOhx3w"),
                    Q = Base64UrlEncoder.DecodeBytes("3fe3gLFi-d1vUm0x1bfU6KYDhv7BMlPcH4a19zH63lXYBsWUfBMGZDxSQIFwmAToXcujB4TNiCZfBNQ-T_l8ew"),
                };

            RsaParameters_1024_Public =
                new RSAParameters
                {
                    Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                    Modulus = Base64UrlEncoder.DecodeBytes("0wo_dwRBLTtIP_bkGrJXAP9dh8YNfXfPmhwjc4uL-MrBdj4llx4juEEojVIF4lUj_dbljpK4x6-sv4auvn7GtSryDvIduXnO9zwY_DFpA5sN8_UXHfE7fCw_WAk5gZxIdMNeqUi0QCi38EO8-7OMjn3dG3fwyfSBogUWvPm9uiU"),
                };

            byte[] cspbytes_2048 = Base64UrlEncoder.DecodeBytes("BwIAAACkAABSU0EyAAgAAAEAAQCP7GdRPSJ5_SDCM4mQsuRP72_P19sw7w7qStb9CXj4aun9iY81bhXI8YjGHZPDrhaSi4bwhGIx5JTNsxBejBTU0QOsLqb8IvlabEHD7T2J4GfIsNwh5u_u8chKMRWeUkxqLzaXdVwickmtvG7t7BjghMzl6Ubwv1DL9prH-pkH56fTqbsu1EwEF4DxWS6RBg1DKNzlmtt5SYYmNksH89yXUV5118YY0UMxJZd3a4Ir_r8wNq4ZtotCAyTfLnCKryTLPrJUcduPlTnjXeegPTFH57fK_UQjq3RGOeTkiDLvKrjQ2FRgXtLdHhXDbAqjQPX0_oruXb78kBxMf0sWa-HrmZTz2hg-VrxNsnJPS-2f-4_MIa8q2dOfGgbxQxLZM19_3VHG_qcn3sXPiVzEwjTvR8edj6wCQ96SYAOkSWByuMplbrzFMfq37u0x6JhOrbkBKWgnU0FO8JvMnAO6jpxNifsWjLkk-ca-JDbzX1L_5u54pHNE76rlEe6oKwvCq_1nG3MI3d_X623S9aQwFw94UGseJfma-6tRAj95LniiXBD7ifjLpCeZvO2W_iLHOOp2WB7DSrNQ_rLfRoStq9DxQY8To4O2SMYPQT7To6tRhRV7lsVuzoGrJIlurXjGXeGBD2gvBTy2_7qhE8ZKiYun67JpIsrN84LkM2pKRtgL7gG1kwCRFEPH_7Pl4JUMCV6kv1DeWCdKlz6fFMatcvN_MUQDBdzjpkgabhc7O_-gBCJp71gnIKsQeMNG_LBxKP0wVZBOtCW3bBmNUSHNZF5CMr7TD7TxXNP6K5sDafOc9_vHz2lkxDDaurY659PrXifpdYFKheHeGPB4nZs697MS-3AARGqCDdoekJft6mF613pzUTOBEc00hm0ehVWVent58JU3ThmcIkImGKxgWaCpaEunlcGVgmpJG562zYPWPTUzsmDnTjciCSZMw_F8PdKzN5kU73JX1yY8k0Oh3ETOxl-uFRGPOiucAeCmvw-9_Mkmyjcrv4Xsk9ftE7ZssGH-F3_O4CMGbQVnsBSpAnO8Yi0f3a9vhipydlTzqpUK7LCoRn4gWVDdsbSmlv-2zjypk_BpgoB4L6ASJOyRySk4KoYSSs38yLEg8SQyNSR95GWZJPEmZhxi5R_03TZcaicn_YCMyfNf9hLmNy8zHetIz8An2qLoZv8w-FglW2O5lXFdKgRb_W-Af2GcjyWGWsMywGEsE6p7A8Ytm8RrwZueTcib_YPFG6_Q4rHHGxcbA_fbz6GKLXrx9oY3xZfNi_3ebPE2aci3CXtoWkH3FRW6kZvGnQsHxxfBww3dogWdV9a0nVdBkfVOD8gfTdCLO8RfARUt1UYwdO22aUqSbxlnxdSgrzFKePsGp_iHCNDZlWeQOIXCIjg2oQLPPT8LYKJrxeWMsyhUw3KlK7cuU_STNLO8CmFD7p025xCrzpK1cC4VeODjur7nB-zuLdmjn-JbLSv0ky9eTNyTkkguhcBbpejM8wEuE3R-HKmV6SrgL8OlhAYBneVIpFP9h2UGoQs");
            byte[] cspbytes_2048_Public = Base64UrlEncoder.DecodeBytes("BgIAAACkAABSU0ExAAgAAAEAAQCP7GdRPSJ5_SDCM4mQsuRP72_P19sw7w7qStb9CXj4aun9iY81bhXI8YjGHZPDrhaSi4bwhGIx5JTNsxBejBTU0QOsLqb8IvlabEHD7T2J4GfIsNwh5u_u8chKMRWeUkxqLzaXdVwickmtvG7t7BjghMzl6Ubwv1DL9prH-pkH56fTqbsu1EwEF4DxWS6RBg1DKNzlmtt5SYYmNksH89yXUV5118YY0UMxJZd3a4Ir_r8wNq4ZtotCAyTfLnCKryTLPrJUcduPlTnjXeegPTFH57fK_UQjq3RGOeTkiDLvKrjQ2FRgXtLdHhXDbAqjQPX0_oruXb78kBxMf0sWa-Hr");

            RsaParameters_2048 =
                new RSAParameters
                {
                    D = Base64UrlEncoder.DecodeBytes("C6EGZYf9U6RI5Z0BBoSlwy_gKumVqRx-dBMuAfPM6KVbwIUuSJKT3ExeL5P0Ky1b4p-j2S3u7Afnvrrj4HgVLnC1ks6rEOc2ne5DYQq8szST9FMutyulcsNUKLOM5cVromALPz3PAqE2OCLChTiQZ5XZ0AiH-KcG-3hKMa-g1MVnGW-SSmm27XQwRtUtFQFfxDuL0E0fyA9O9ZFBV5201ledBaLdDcPBF8cHC53Gm5G6FRX3QVpoewm3yGk28Wze_YvNl8U3hvbxei2Koc_b9wMbFxvHseLQrxvFg_2byE2em8FrxJstxgN7qhMsYcAyw1qGJY-cYX-Ab_1bBCpdcQ"),
                    DP = Base64UrlEncoder.DecodeBytes("ErP3OpudePAY3uGFSoF16Sde69PnOra62jDEZGnPx_v3nPNpA5sr-tNc8bQP074yQl5kzSFRjRlstyW0TpBVMP0ocbD8RsN4EKsgJ1jvaSIEoP87OxduGkim49wFA0Qxf_NyrcYUnz6XSidY3lC_pF4JDJXg5bP_x0MUkQCTtQE"),
                    DQ = Base64UrlEncoder.DecodeBytes("YbBsthPt15Pshb8rN8omyfy9D7-m4AGcKzqPERWuX8bORNyhQ5M8JtdXcu8UmTez0j188cNMJgkiN07nYLIzNT3Wg822nhtJaoKVwZWnS2ipoFlgrBgmQiKcGU43lfB5e3qVVYUebYY0zRGBM1Fzetd6Yertl5Ae2g2CakQAcPs"),
                    Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                    InverseQ = Base64UrlEncoder.DecodeBytes("lbljWyVY-DD_Zuii2ifAz0jrHTMvN-YS9l_zyYyA_Scnalw23fQf5WIcZibxJJll5H0kNTIk8SCxyPzNShKGKjgpyZHsJBKgL3iAgmnwk6k8zrb_lqa0sd1QWSB-Rqiw7AqVqvNUdnIqhm-v3R8tYrxzAqkUsGcFbQYj4M5_F_4"),
                    Modulus = Base64UrlEncoder.DecodeBytes("6-FrFkt_TByQ_L5d7or-9PVAowpswxUe3dJeYFTY0Lgq7zKI5OQ5RnSrI0T9yrfnRzE9oOdd4zmVj9txVLI-yySvinAu3yQDQou2Ga42ML_-K4Jrd5clMUPRGMbXdV5Rl9zzB0s2JoZJedua5dwoQw0GkS5Z8YAXBEzULrup06fnB5n6x5r2y1C_8Ebp5cyE4Bjs7W68rUlyIlx1lzYvakxSnhUxSsjx7u_mIdywyGfgiT3tw0FsWvki_KYurAPR1BSMXhCzzZTkMWKE8IaLkhauw5MdxojxyBVuNY-J_elq-HgJ_dZK6g7vMNvXz2_vT-SykIkzwiD9eSI9UWfsjw"),
                    P = Base64UrlEncoder.DecodeBytes("_avCCyuo7hHlqu9Ec6R47ub_Ul_zNiS-xvkkuYwW-4lNnI66A5zMm_BOQVMnaCkBua1OmOgx7e63-jHFvG5lyrhyYEmkA2CS3kMCrI-dx0fvNMLEXInPxd4np_7GUd1_XzPZEkPxBhqf09kqryHMj_uf7UtPcrJNvFY-GNrzlJk"),
                    Q = Base64UrlEncoder.DecodeBytes("7gvYRkpqM-SC883KImmy66eLiUrGE6G6_7Y8BS9oD4HhXcZ4rW6JJKuBzm7FlnsVhVGro9M-QQ_GSLaDoxOPQfHQq62ERt-y_lCzSsMeWHbqOMci_pbtvJknpMv4ifsQXKJ4Lnk_AlGr-5r5JR5rUHgPFzCk9dJt69ff3QhzG2c"),
                };

            RsaParameters_2048_Public =
                new RSAParameters
                {
                    Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                    Modulus = Base64UrlEncoder.DecodeBytes("6-FrFkt_TByQ_L5d7or-9PVAowpswxUe3dJeYFTY0Lgq7zKI5OQ5RnSrI0T9yrfnRzE9oOdd4zmVj9txVLI-yySvinAu3yQDQou2Ga42ML_-K4Jrd5clMUPRGMbXdV5Rl9zzB0s2JoZJedua5dwoQw0GkS5Z8YAXBEzULrup06fnB5n6x5r2y1C_8Ebp5cyE4Bjs7W68rUlyIlx1lzYvakxSnhUxSsjx7u_mIdywyGfgiT3tw0FsWvki_KYurAPR1BSMXhCzzZTkMWKE8IaLkhauw5MdxojxyBVuNY-J_elq-HgJ_dZK6g7vMNvXz2_vT-SykIkzwiD9eSI9UWfsjw"),
                };

            byte[] cspbytes_4096 = Base64UrlEncoder.DecodeBytes("BwIAAACkAABSU0EyABAAAAEAAQCZrcZ3JOjYvkjBZwkC_ukZook4u8se9AjHSP6bySfv69VLwlQLAREu-qz13lsoylKxVT4Abz2TxI4oLKKogKAdinRoNRYrIidsbOe6wHbsxreV6Qt4aiU_YdR0PnisyIx9jnheWtcO-_PCW5dQv9-OnjbnKxgy1A5XhHaj-MhL-uVOBKHmk1cXTMcAOzt1XL_oYjxiftg_InHBBT7hG6HrPyritd_np1TckPnuJq5GeajEcwmSIxGNtR4WlTyGD-5MyIVxxWvQgvWjXHDCXp01eA_R-3KImaE62cAULabdKHbNzQFAfJOb-nmAiZU9bhKw7TdZb9Omjr7DadZ8WrqlY7kYmk73IczxX3Vnvm67_Haj7hBrKewJfvQ3SPyqF85CpyNLCrLXzLxVNqEg-YxNkg5Zlf62-t3BA-QHUW7mOIi87iuwvp6WmoZ_o_JEcAl7DY1XlsMVF5v5KrhsAm9FeUQTjFpZkkrFWkgVzBYZ0RpJbDtREgTJXy8764Gq0qcgk7CvC7RkYAtUXj_0rME6nbooLDpKhiQNl9-OLGas-kh9MtR76jTbteToQz2XsIZI3gnJjzpb_BNSvABRqbSgWJ8mVTkGmIc-YImXUqxriE5P4EdulcX5orRkD1LTWiS5tnLqLCUlK-v9SEC0raKx99H5CXl4xv_EDsM2qubzvZXWPbz3kSQY1zhwdKcemx4iIUg69JK7v9PAApf136EVRX3wjVhLUHJfBVAZ0H_VGSCosxmbUuyyh1akiLwzaH1crZz0M9uJ1iS1HZrxpVGn4DuI0A-2ZTP7GAA_q2PjVcNR65LJxAsQmQLHESnWxqA4RZxcxtCukB158isSW6cpxgnsVG2hSHh9spBUaRjzqzejAgh2lrknSJEDSxrfCusdlLmTwbQvOUANAWEpyyVUAnHToFFY6lg6jkJqlAKUdAXw-zPuE3gDaC4fwZL9pCyY-0V2kVW_xusGKg-peiAPGAdaqnL9O0l_tcHrXLNxjySMHPY925ywNf21gTHVfM_1zfc66A_8qv7bAPFMZ-9X0c2Fxq8sGbKDwwj4mnuwB5zRR1wg7YqsvR6XT29h2j7O1VtzJWAfkoMRO_g0cqQP6c9GHPIO9kmLua0KzxRD-KTaQthvgt3x8cn7Ru_NJ3UNDh5cdzt2ieuQFvTGsyoctrRWta9rzb_C0BisBWw-PejJ5yUbFaTi1pJvLOoZTZZ7lCMw5DyRMS3r59Fv7hCY2MI9uIrr4HGOgCdDtYq5Xq4TkKolf887HkuFnUrPsaqk8N-eib1XOlvdyN4YUTlJx6uLTU-kruwEJBZxZ-IRwKDRTG73dVGgf61FSFmD5jpuWNoVkzx2f1UMCYmQhF3qGRIBar0gA7EQCl7IB2TXKuC746nismR2GhlRzktUloCMrzn9OqTgLu39okB4aE_ik1PElT7NDSZNVR41rQtXhHKKOO--Ch4fFv4zlpxErAIB1hu8w4stBx0ZXOyZegHsG0b6JAq0dVjqE357GzypgrrnwvBBDwAW3hPHyHbbKFcjH2N3RRCAHZlsafa_dBHkeevcktWiEarVAhRf0dGjAapoacrL8izb5mr7NGCmg2cwF_F6WvZJhjG5SPSj2HbfLoEkLGUMtDewYK7717_JRFOUEW2OHBfdL0GB0w6hTgLMoKfYXt_rYZw87Bzim5xXLNCZ5BTiWQO4LA8-O3-8oWkHNpNAAPKLXQaGpqopBHa3ujIUQCsINKZuaMMOnl_PFALxGiVY5f9JpHMGtjAVplAZZ4vPZsW7X7O478pwejNRR3_Y4SWNWZglyBamKRxeSz007lwtnbQoywtX72QNvNgpd6jY6zf4h5hNxhZqVg0FVrQUZUBnrA2TkFP3xUDoUOA26IlSf-qKYUus36wxNet-nyoMrAunQ0RubAwE7WWlGmBX-AQ5hXew7Cb-vjhjaZtGecJxQvVIcSBsvBK9Zfp7T85TaRFsHYH_Em8Eysb3grTTNnw6tkx2n43AOML3zyQiSgO4TxwzIINKrDwx94hH4tgBlph636eQLySS3nH0bSUw0pbBZurtkeX3IKYHdsCZfMtmhJUZxLMSLlZILQLm_6GD3I6kHINvGTdhHnZSoS4BecS3vBL3tXa-p_UAvhra8u7YLuGBkM8ZUV3a7OifB0R5TKhf_nyPsJg9_W5HnFvdv1wRsL1u8vdQOFHu4O9iCbLtDs2yTmRo0UTuWBItAqOhDqcU2wA6blptT-t7KhZvfOApK10kvEeDov6ch49JXX0CIQqUe2uzWh7Hc1xVI48ahK9aautS0EpaplbPuipNp1qIGSOOeVkDYPGd0KtjtlI2ZZdvxHu1UDsfZBBc-ngZWPp8IbGFMLIvv_ZnaCwn9hzCBT87WHg9dAEbudMxNw7mBBkjDJWqNFZVWDdeZk-dx2rAC5cM09CCkjjHjX2_eCpztb65lvM0ir1l8tq3SPaz2N9OLwipLRdm8vjWwSRGYaApXqxC4ZgxzSgTm-9Yd4o60zE5JdHyyCZ0DIuHieJ437ut-ozQ5-cV8d2yUrOQWjx97ehixruKZlf8PnOn-0Q48mGtqOJ2gQNiULIpksv7AGxORmRHKoBGQtzjiGfViOxk6hf62-ilAbz7fLeSLVZhG1ixaQWXkWeSf9G27mgEvt3IfrSJLmb4tMsspeYFYdjlTtkz1XBbpuv-F6-vhbgRnQQeR9OAa5BAtsFHvDU2KSOfkJfqWVQ9ffxriCTY3R1og4U52-Jdt64IlA-7-ZBbourBEbuCti8wC0UsjgtH4uAhhu4I7Td8ja-l2MJAGu5kvOoGRvg09ClyW3Top7Bmr7YkKchSjwyrPwhJtn5edl_N9p7i_1uHTrzTmNW7z4_g8NZl1oy2F14KQXCrjo8Kw_gt7D43nu9A2MXEYvIxEoaRu6SJJh8dL-Wfjo4dNsNS6iq-RxGtlJigMRV_lAG6n9U2YPws3xj6cTRiAnRcJcpRm8QyHoE-BlxWV739ENQXcno-qpYOT6UMO-wwCTU0x92rrDAL9ow4TkjX3VrMV9B1BLUFakDfj_pRp5P4bBMtMah20CZEXgc");
            byte[] cspbytes_4096_Public = Base64UrlEncoder.DecodeBytes("BgIAAACkAABSU0ExABAAAAEAAQCZrcZ3JOjYvkjBZwkC_ukZook4u8se9AjHSP6bySfv69VLwlQLAREu-qz13lsoylKxVT4Abz2TxI4oLKKogKAdinRoNRYrIidsbOe6wHbsxreV6Qt4aiU_YdR0PnisyIx9jnheWtcO-_PCW5dQv9-OnjbnKxgy1A5XhHaj-MhL-uVOBKHmk1cXTMcAOzt1XL_oYjxiftg_InHBBT7hG6HrPyritd_np1TckPnuJq5GeajEcwmSIxGNtR4WlTyGD-5MyIVxxWvQgvWjXHDCXp01eA_R-3KImaE62cAULabdKHbNzQFAfJOb-nmAiZU9bhKw7TdZb9Omjr7DadZ8WrqlY7kYmk73IczxX3Vnvm67_Haj7hBrKewJfvQ3SPyqF85CpyNLCrLXzLxVNqEg-YxNkg5Zlf62-t3BA-QHUW7mOIi87iuwvp6WmoZ_o_JEcAl7DY1XlsMVF5v5KrhsAm9FeUQTjFpZkkrFWkgVzBYZ0RpJbDtREgTJXy8764Gq0qcgk7CvC7RkYAtUXj_0rME6nbooLDpKhiQNl9-OLGas-kh9MtR76jTbteToQz2XsIZI3gnJjzpb_BNSvABRqbSgWJ8mVTkGmIc-YImXUqxriE5P4EdulcX5orRkD1LTWiS5tnLqLCUlK-v9SEC0raKx99H5CXl4xv_EDsM2qubzvQ");

            RsaParameters_4096 =
                new RSAParameters
                {
                    D = Base64UrlEncoder.DecodeBytes("B15EJtB2qDEtE2z4k6dR-o_fQGoFtQR10FfMWt3XSE44jPYLMKyr3cc0NQkw7DsMpU8Olqo-enIX1BD9vVdWXAY-gR4yxJtRyiVcdAJiNHH6GN8s_GA21Z-6AZR_FTGgmJStEUe-KupSwzYdjo6f5S8dHyaJpLuRhhIx8mLExdhA7543Puwt-MMKj46rcEEKXhe2jNZl1vDgj8-71ZjTvE6HW__invbNX3ZefrZJCD-rDI9SyCkktq9msKfodFtyKfQ0-EYG6rxk7hpAwtilr418N-0I7oYh4OJHC44sRQswL7aCuxHB6qJbkPm7D5QIrrdd4ts5hYNoHd3YJIhr_H09VFnql5CfIyk2NbxHwbZAkGuA00ceBJ0RuIWvrxf-66ZbcNUz2U7l2GEF5qUsy7T4Zi6JtH7I3b4EaO620X-SZ5GXBWmxWBthVi2St3z7vAGl6Nv6F-pk7IjVZ4jj3EJGgCpHZEZObAD7y5IpslBiA4F24qitYfI4RPuncz78V2aKu8Zi6O19PFqQs1Ky3fEV5-fQjPqtu9944omHiwx0Jsjy0SU5MdM6indY75sTKM0xmOFCrF4poGFGJMHW-PJmFy2pCC9O39iz9ki32vJlvYo085a5vrVzKni_fY3HOJKC0NMMlwvAasedT2ZeN1hVVjSqlQwjGQTmDjcx07k"),
                    DP = Base64UrlEncoder.DecodeBytes("obx_Oz4PLLgDWeIU5JnQLFecm-Ic7DycYevfXtinoMwCTqEO04FBL90XHI5tEZRTRMm_1_uuYLA3tAxlLCSBLt922KP0SLkxhkn2WnrxFzBng6ZgNPtq5tss8svKaWiqAaPR0V8UAtWqEaLVktzreeQRdL_2aWyZHYAQRXdjHyNXKNt2yMcT3hYAD0Hwwue6gqk8G3t-E-pYdbQKJPpGG-wBepnsXBkdBy2Lw7wb1gECrEScljP-Fh8eCr7vOIpyhFcLrTUeVU0mDc0-lcRTk-JPaHhAov3tLuCkOv05r4yAllRLzlEZGnZksuKp47vgKtdkB8heChCxAyC9agESGQ"),
                    DQ = Base64UrlEncoder.DecodeBytes("cd6SJC-Qp996mJYB2OJHiPcxPKxKgyAzHE-4A0oiJM_3wjjAjZ92TLY6fDbTtIL3xsoEbxL_gR1sEWlTzk97-mW9ErxsIHFI9UJxwnlGm2ljOL7-Juywd4U5BPhXYBqlZe0EDGxuREOnC6wMKp9-6zUxrN-sS2GK6n9Sieg24FDoQMX3U5CTDaxnQGUUtFYFDVZqFsZNmIf4N-vYqHcp2LwNZO9XC8sotJ0tXO40PUteHCmmFsglmFmNJeHYf0dRM3pwyu-4s1-7xWbPi2cZUKYVMLYGc6RJ_-VYJRrxAhTPX54Ow2hupjQIK0AUMrq3dgQpqqaGBl2L8gBAkzYHaQ"),
                    Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                    InverseQ = Base64UrlEncoder.DecodeBytes("GwF0PXhYOz8Fwhz2JyxoZ_a_L7IwhbEhfPpYGXj6XBBkHztQtXvEb5dlNlK2Y6vQnfFgA1l5jiMZiFqnTSq6z1amWkrQUutqWq-EGo8jVVxzxx5as2t7lAohAn1dSY-HnP6ig0e8JF0rKeB8bxYqe-tPbVpuOgDbFKcOoaMCLRJY7kTRaGROss0O7bIJYu_g7lE4UPfybr2wEVy_3VucR279PZiwj3z-X6hMeUQHn-js2l1RGc-QgeEu2O7y2hq-APWnvna19xK8t8R5AS6hUnYeYTcZb4McpI7cg6H_5gItSFYuErPEGZWEZst8mcB2B6Yg9-WR7epmwZbSMCVt9A"),
                    Modulus = Base64UrlEncoder.DecodeBytes("vfPmqjbDDsT_xnh5CfnR97GirbRASP3rKyUlLOpytrkkWtNSD2S0ovnFlW5H4E9OiGusUpeJYD6HmAY5VSafWKC0qVEAvFIT_Fs6j8kJ3kiGsJc9Q-jktds06nvUMn1I-qxmLI7flw0khko6LCi6nTrBrPQ_XlQLYGS0C6-wkyCn0qqB6zsvX8kEElE7bEka0RkWzBVIWsVKkllajBNEeUVvAmy4KvmbFxXDlleNDXsJcETyo3-GmpaevrAr7ryIOOZuUQfkA8Hd-rb-lVkOkk2M-SChNlW8zNeyCksjp0LOF6r8SDf0fgnsKWsQ7qN2_Ltuvmd1X_HMIfdOmhi5Y6W6WnzWacO-jqbTb1k37bASbj2ViYB5-puTfEABzc12KN2mLRTA2TqhmYhy-9EPeDWdXsJwXKP1gtBrxXGFyEzuD4Y8lRYetY0RI5IJc8SoeUauJu75kNxUp-ffteIqP-uhG-E-BcFxIj_YfmI8Yui_XHU7OwDHTBdXk-ahBE7l-kvI-KN2hFcO1DIYK-c2no7fv1CXW8Lz-w7XWl54jn2MyKx4PnTUYT8langL6ZW3xux2wLrnbGwnIisWNWh0ih2ggKiiLCiOxJM9bwA-VbFSyihb3vWs-i4RAQtUwkvV6-8nyZv-SMcI9B7LuziJohnp_gIJZ8FIvtjoJHfGrZk"),
                    P = Base64UrlEncoder.DecodeBytes("z3zVMYG1_TWwnNs99hyMJI9xs1zrwbV_STv9cqpaBxgPIHqpDyoG68a_VZF2RfuYLKT9ksEfLmgDeBPuM_vwBXSUApRqQo46WOpYUaDTcQJUJcspYQENQDkvtMGTuZQd6wrfGksDkUgnuZZ2CAKjN6vzGGlUkLJ9eEihbVTsCcYpp1sSK_J5HZCu0MZcnEU4oMbWKRHHApkQC8TJkutRw1XjY6s_ABj7M2W2D9CIO-CnUaXxmh21JNaJ2zP0nK1cfWgzvIikVoey7FKbGbOoIBnVf9AZUAVfclBLWI3wfUUVod_1lwLA07-7kvQ6SCEiHpsep3RwONcYJJH3vD3WlQ"),
                    Q = Base64UrlEncoder.DecodeBytes("6l2EkIkJDFV_djyTFdpYbjrmg1lIRa1_oFF1925M0aDAEeJncRYkBOyupE9Ni6vHSTlRGN7I3Vs6V72Jnt_wpKqxz0qdhUseO89_JaqQE65euYq1QyeAjnHg64q4PcLYmBDub9Hn6y0xkTzkMCOUe5ZNGeosb5LW4qQVGyXnyeg9PmwFrBjQwr_Na6-1VrS2HCqzxvQWkOuJdjt3XB4ODXUnze9G-8nx8d2Cb9hC2qT4QxTPCq25i0n2DvIcRs_pD6RyNPg7EYOSH2Alc1vVzj7aYW9Plx69rIrtIFxH0ZwHsHua-AjDg7IZLK_Ghc3RV-9nTPEA2_6q_A_oOvfN9Q"),

                };

            RsaParameters_4096_Public =
                new RSAParameters
                {
                    Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                    Modulus = Base64UrlEncoder.DecodeBytes("vfPmqjbDDsT_xnh5CfnR97GirbRASP3rKyUlLOpytrkkWtNSD2S0ovnFlW5H4E9OiGusUpeJYD6HmAY5VSafWKC0qVEAvFIT_Fs6j8kJ3kiGsJc9Q-jktds06nvUMn1I-qxmLI7flw0khko6LCi6nTrBrPQ_XlQLYGS0C6-wkyCn0qqB6zsvX8kEElE7bEka0RkWzBVIWsVKkllajBNEeUVvAmy4KvmbFxXDlleNDXsJcETyo3-GmpaevrAr7ryIOOZuUQfkA8Hd-rb-lVkOkk2M-SChNlW8zNeyCksjp0LOF6r8SDf0fgnsKWsQ7qN2_Ltuvmd1X_HMIfdOmhi5Y6W6WnzWacO-jqbTb1k37bASbj2ViYB5-puTfEABzc12KN2mLRTA2TqhmYhy-9EPeDWdXsJwXKP1gtBrxXGFyEzuD4Y8lRYetY0RI5IJc8SoeUauJu75kNxUp-ffteIqP-uhG-E-BcFxIj_YfmI8Yui_XHU7OwDHTBdXk-ahBE7l-kvI-KN2hFcO1DIYK-c2no7fv1CXW8Lz-w7XWl54jn2MyKx4PnTUYT8langL6ZW3xux2wLrnbGwnIisWNWh0ih2ggKiiLCiOxJM9bwA-VbFSyihb3vWs-i4RAQtUwkvV6-8nyZv-SMcI9B7LuziJohnp_gIJZ8FIvtjoJHfGrZk"),
                };

            RsaSecurityKey_1024 = new RsaSecurityKey(RsaParameters_1024);
            RsaSecurityKey_1024_Public = new RsaSecurityKey(RsaParameters_1024_Public);
            RsaSecurityKey_2048 = new RsaSecurityKey(RsaParameters_2048);
            RsaSecurityKey_2048_Public = new RsaSecurityKey(RsaParameters_2048_Public);
            RsaSecurityKey_4096 = new RsaSecurityKey(RsaParameters_4096);
            RsaSecurityKey_4096_Public = new RsaSecurityKey(RsaParameters_4096_Public);
            RSASigningCreds_1024 = new SigningCredentials(RsaSecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            RSASigningCreds_1024_Public = new SigningCredentials(RsaSecurityKey_1024_Public, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            RSASigningCreds_2048 = new SigningCredentials(RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            RSASigningCreds_2048_Public = new SigningCredentials(RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            RSASigningCreds_4096 = new SigningCredentials(RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            RSASigningCreds_4096_Public = new SigningCredentials(RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
        }

        // all asymmetric material has private key unless public is included in variable name
        public const string CertPassword = "abcd";

        public const string X509Data_AAD_Public =@"MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng";
        public static X509Certificate2 Cert_AAD_Public = new X509Certificate2(Convert.FromBase64String(X509Data_AAD_Public));
        public static X509SecurityKey X509SecurityKey_AAD_Public = new X509SecurityKey(Cert_AAD_Public);
        public static SigningCredentials X509SigningCreds_AAD_Public = new SigningCredentials(X509SecurityKey_AAD_Public, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

        public const string X509Data_LocalSts =  @"MIIG/wIBAzCCBrsGCSqGSIb3DQEHAaCCBqwEggaoMIIGpDCCA8UGCSqGSIb3DQEHAaCCA7YEggOyMIIDrjCCA6oGCyqGSIb3DQEMCgECoIICtjCCArIwHAYKKoZIhvcNAQwBAzAOBAgxJ3VQ0iw/xwICB9AEggKQpGXp1k8GPfQoWaPJ0laxuR3wjejEWhAIHFOeeYiV4d0LJJ1rl1QwlnaArY7hDbL2KxMuDXQpa4vRVAuze2uW/BfxXGK8mFkClDkLa90zYWl7Bgn+I1dq5ngGjefaZ1Jecm12aMDdm2KgCtDCZMypJroa53ixrfah7PoF39vFOP9EELugF/HbGHbJrqGQlJxHhL3A7TCTt2B6DwhsoNupqhYKjt0W6W3p8mLrNKjM7DDJehMSN+RJKXit6p/XnncRsaML0NHoz8Ubys9+2zWVEc3daUc1AQV5W01WDENxC9JerDnwLhwv+JW8d0Y6I02tHvZJnEHSSPQLyZ5xGAg0AlcEjcN6+AbPKbl7hRM3mKyvzBuInA5Dpr9D1dOaa+FrzoxF5TkaWjH2XKpbv0zL4bpSqPq23IgWT1Xgr9mqBojig5jKrHO9K3eGC/UxVcdIymbaovgNY2mAG64FmCTgKc0HFGkjY6q8TxgTzLSOQgdoZjL3FQN85urlpKLd4LVSoxJAy0lCTlJFsZGdv2XOoNwWUGkGllEWkAGQHvUGSkPCW9S3R8zMrb/7L0q35Npk+owVETCqsm/+uHwDrhKHhDmEDaLbdgC6G16oMsctmqPoARcW8+5RoD3pT6jnPYGZbukcOzVzGFjLO70umpTmk8aw/8Y2jY5TStnMqdOw21RuSTPepv36Vk7EG3fd3rmddtyY+tr5wmpJyXFJjgavKMR45TqOBXC+/I59xbO9H40BvTkvlwqs7v825xNDHVZaDnfULpeAixNrt2rr8puhqlSiY7bE5V3RATSZF/FMUliaZd2b+XYcwEdaoKcQ/QFPTQj3IXBNvwtx3lZniiGaVCDoR1v0yc+ViUVg2RtXibMxgeAwDQYJKwYBBAGCNxECMQAwEwYJKoZIhvcNAQkVMQYEBAEAAAAwWwYJKoZIhvcNAQkUMU4eTAB7ADEARQAxADYANQBCAEYAQQAtADUAMwA1AEIALQA0AEEAOABEAC0AOABEADkAMgAtADIANwAzAEEANQA1ADgAMQBCADIAQQBCAH0wXQYJKwYBBAGCNxEBMVAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAdAByAG8AbgBnACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcjCCAtcGCSqGSIb3DQEHBqCCAsgwggLEAgEAMIICvQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIziGrBRDWdnQCAgfQgIICkIlezl4wsBhEcM0r4tXf3gpVSHQ242FsqqJGR6lGl97TIbC7lBHShbnpVqZLkHdem57rMtHMsQu0TEr18zU81E6rJ620734KWfc2cCXN9z6ec03TKimjrYpJLo8Aw+3nShJ/e9BeXstVMWuf1PU4NCrBIxcRUA4dNL5Z56u6uV8FmHztfBqzoTWkm0KpFrHILShWphKvhMLcwtp+XyC17WgbXNxvXn9dyarC9XuygGySKlJaapLRYKqR1PCIFz7X/mn0DO4P69nkJGEvEFORNKBYoGS2+rufxMniA1O/+58/FXHGf9HfhAvYuAThyZCyqRFvc4cfd03aYYVwbN+/+9e8ryXfqO9rCaEdc4HygVNhiChjoM8NMlZL5+R4L9tHr78uCPIzN0gyzL3wcWipmBNWYaG0bffbCyY4gILMvZGD1bEFpPL9wS+VRiLm3tmpLcrhJgCBGYgdkFL6WCWzHQy2tk4yqp+3nTm+8MjV2IafLquzICeqq3aplWkDlFU0IEVfPI8eMi62YsBhVpez4cn6tee3DyVoIYTFuX1qAVUs9JJFmbec12gO2UI2X/f2Iu/iTD655Kpshm3FiyanBrXlTJUGa6mUGbI3YP5Uwgxupyh1YH3uuhNFaejRQ4T1fS3n0MEN3Th27FaH7jDA7wNenfctvokIQv2h4Sa06vcwFkzMRp02GCC/kyD8+7fqkEFAQGdOv0Gt+a97qs9IAVUNN/wOIkAkQ8Yn6lloowps70oOATE8ht3Z5+mVJDXQe5w7kzUVHOxjWxS8rW8CosHshHbKzDdwNsx0syQ33C+vasdE5PeMktbglvHNEg2AzdnH5yoNkf77+R6fLNbX8xVJXKX/nGBYN+u+3+iTVH1NMDswHzAHBgUrDgMCGgQUiwmNMPt0QB2eI9Jb0gi6nqnmEOIEFNY15fRBiXJYAwaPVCRLqAaQYuDAAgIH0AAA";
        public static X509Certificate2 Cert_LocalSts = new X509Certificate2( Convert.FromBase64String( X509Data_LocalSts ), CertPassword, X509KeyStorageFlags.MachineKeySet );
        public static X509SecurityKey X509SecurityKey_LocalSts = new X509SecurityKey( Cert_LocalSts );
        public static SigningCredentials X509SigningCreds_LocalSts  = new SigningCredentials(X509SecurityKey_LocalSts, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

        // 1024 bit RSA
        public const string X509Data_1024 = @"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";
        public static X509Certificate2 Cert_1024 = new X509Certificate2( Convert.FromBase64String( X509Data_1024 ), CertPassword, X509KeyStorageFlags.MachineKeySet );
        public static X509SecurityKey X509SecurityKey_1024 = new X509SecurityKey( Cert_1024 );
        public static SigningCredentials X509SigningCreds_1024_RsaSha2_Sha2  = new SigningCredentials(X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );

        // 2048 bit RSA
        public const string DefaultX509Data_2048 = @"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";
        public static X509Certificate2 DefaultCert_2048 = new X509Certificate2( Convert.FromBase64String( DefaultX509Data_2048 ), CertPassword, X509KeyStorageFlags.MachineKeySet );
        public static X509SecurityKey DefaultX509Key_2048 = new X509SecurityKey( DefaultCert_2048 );
        public static SigningCredentials DefaultX509SigningCreds_2048_RsaSha2_Sha2  = new SigningCredentials(DefaultX509Key_2048, SecurityAlgorithms.RsaSha256Signature, "foo");
        public static X509Certificate2 DefaultAsymmetricCert_2048 = new X509Certificate2( Convert.FromBase64String( DefaultX509Data_2048 ), CertPassword, X509KeyStorageFlags.MachineKeySet );

        public static string DefaultX509Data_Public_2048                                    = @"MIICyjCCAbKgAwIBAgIQJPMYqnyiTY1GQYAwZxadMjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDExZBREZTIFNpZ25pbmcgLSBTVFMuY29tMB4XDTEyMTAwOTIyMTA0OVoXDTEzMTAwOTIyMTA0OVowITEfMB0GA1UEAxMWQURGUyBTaWduaW5nIC0gU1RTLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMmeVPJz8o7ayB3AS2dJtsIo/eXqeNhZ+ZqEJgHVHc0JAAgNNwR++moMt8+iIlOKZiAL8dvQBKOuPms+FfqrG1HshnMiLcuadtWUqOntxUdyQLcEKvdaFOqOppqmasqGFtRLPwYKIkZOkj8ikndNzI6PZV46mw18nLaN6rTByMnjVA5n9Lf7Cdu7lmxlKGJOI5F0IfeaW68/kY1bdw3KAEb1aOKHj0r7RJ2joRuHJ+96kw1bA2T6bGC/1LYND3DFsnQQtMBl7LlDrSG1gGoiZxCoQmPCxfrTCrYKGK6y9j6IQ4MCmJpnt0l/INL5i88TjctF4IkJwbJGn9iY2fIIBxMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAq/SyHGCLpBm+Gmh5I7BAWJXvtPaIelt30WgKVXRHccxRVIYpKOfAA2iPuD/CVruFz6pnP4K7o2KLAs+XJptigYzLEjKw6rY4836ZJC8m5kfBVanu45OW39nxzxp1udbxQ5gAdmvnY/2agpFhCFR8M1BtWON6G3SzHwo2dXHh+ettOO2LtK38e1+Uy+KGowRw/m4gprSIvgN3AAo7e0PnFblZn6vRgMsK60QB5D8f+Kxdg2I3ZGQcPBQI2fpjEDQCZVc2LV4ywPX4QDPfmYjn+1IaU9w7unbh+oUGQsrdKw3gsdzWEsX/IMXTDf46FEOjV+JqE7VilzcNuDcQ0x9K8gAA";
        public static X509Certificate2 DefaultCertPublic_2048                               = new X509Certificate2( Convert.FromBase64String( DefaultX509Data_Public_2048 ) );
        public static X509SecurityKey DefaultX509Key_Public_2048                            = new X509SecurityKey( DefaultCertPublic_2048 );
        public static SigningCredentials DefaultX509SigningCreds_Public_2048_RsaSha2_Sha2   = new SigningCredentials(DefaultX509Key_Public_2048, SecurityAlgorithms.RsaSha1Signature, SecurityAlgorithms.Sha256Digest );

        // RSA securityKey
        public static RSAParameters RsaParameters_1024;
        public static RSAParameters RsaParameters_1024_Public;
        public static RSAParameters RsaParameters_2048;
        public static RSAParameters RsaParameters_2048_Public;
        public static RSAParameters RsaParameters_4096;
        public static RSAParameters RsaParameters_4096_Public;

        public static RsaSecurityKey RsaSecurityKey_1024;
        public static RsaSecurityKey RsaSecurityKey_1024_Public;
        public static RsaSecurityKey RsaSecurityKey_2048;
        public static RsaSecurityKey RsaSecurityKey_2048_Public;
        public static RsaSecurityKey RsaSecurityKey_4096;
        public static RsaSecurityKey RsaSecurityKey_4096_Public;

        public static SigningCredentials RSASigningCreds_1024;
        public static SigningCredentials RSASigningCreds_1024_Public;
        public static SigningCredentials RSASigningCreds_2048;
        public static SigningCredentials RSASigningCreds_2048_Public;
        public static SigningCredentials RSASigningCreds_4096;
        public static SigningCredentials RSASigningCreds_4096_Public;

#if SymmetricKeySuport
        public static string DefaultSymmetricKeyEncoded_256                    ="Vbxq2mlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE=";
        public static byte[] DefaultSymmetricKeyBytes_256                      = Convert.FromBase64String( DefaultSymmetricKeyEncoded_256 );
        public static SymmetricSecurityKey DefaultSymmetricSecurityKey_256     = new SymmetricSecurityKey( DefaultSymmetricKeyBytes_256 );
        public static SigningCredentials DefaultSymmetricSigningCreds_256_Sha2 = new SigningCredentials( DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest );

        // used in negative cases
        public static string SymmetricKeyEncoded2_256                     ="VbbbbmlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE=";
        public static byte[] SymmetricKeyBytes2_256                       = Convert.FromBase64String( SymmetricKeyEncoded2_256 );
        public static SymmetricSecurityKey SymmetricSecurityKey2_256      = new SymmetricSecurityKey( SymmetricKeyBytes2_256 );

        public static SymmetricSecurityKey SymmetricSecurityKey_56 = new SymmetricSecurityKey(new byte[7]);

        // These signingCreds have algorithms and hashs that are not supported
        public static SigningCredentials SymmetricSigningCreds_256_Rsa256_Sha2      = new SigningCredentials( DefaultSymmetricSecurityKey_256, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );
        public static SigningCredentials SymmetricSigningCreds_256_Rsa256_Sha1      = new SigningCredentials( DefaultSymmetricSecurityKey_256, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha1Digest );
        public static SigningCredentials SymmetricSigningCreds_2048RSA_H256_Sha2    = new SigningCredentials(RsaSecurityKey_2048, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest );
#endif

    }
}