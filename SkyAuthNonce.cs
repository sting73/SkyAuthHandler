using System;
using System.Security.Cryptography;

namespace SkyAuthHandler
{
    class SkyAuthNonce
    {
        private static int DEFAULT_MIN_KEY_LENGTH = 8;
        private static int DEFAULT_MAX_KEY_LENGTH = 12;

        private static string KEY_CHARS_LCASE = "abcdefgijkmnopqrstwxyz";
        private static string KEY_CHARS_UCASE = "ABCDEFGHJKLMNPQRSTWXYZ";
        private static string KEY_CHARS_NUMERIC = "0123456789";

        public string Generate()
        {
            return Generate(DEFAULT_MIN_KEY_LENGTH, DEFAULT_MAX_KEY_LENGTH);
        }

        public string Generate(int length)
        {
            return Generate(length, length);
        }

        private string Generate(int minLength, int maxLength)
        {
            if (minLength <= 0 || maxLength <= 0 || minLength > maxLength)
                return null;

            char[][] charGroups = new char[][]
            {
                KEY_CHARS_LCASE.ToCharArray(),
                KEY_CHARS_UCASE.ToCharArray(),
                KEY_CHARS_NUMERIC.ToCharArray()
            };

            int[] charsLeftInGroup = new int[charGroups.Length];

            for (int i = 0; i < charsLeftInGroup.Length; i++)
            {
                charsLeftInGroup[i] = charGroups[i].Length;
            }

            int[] leftGroupsOrder = new int[charGroups.Length];

            for (int i = 0; i < leftGroupsOrder.Length; i++)
            {
                leftGroupsOrder[i] = i;
            }

            byte[] randomBytes = new byte[4];

            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomBytes);

            int seed = (randomBytes[0] & 0x7f) << 24 |
                        randomBytes[1] << 16 |
                        randomBytes[2] << 8 |
                        randomBytes[3];

            Random random = new Random(seed);

            char[] key = null;

            if (minLength < maxLength)
                key = new char[random.Next(minLength, maxLength - 1)];
            else
                key = new char[minLength];

            int nextCharIdx;
            int nextGroupIdx;
            int nextLeftGroupOrderIdx;
            int lastCharIdx;
            int lastLeftGroupsOrderIdx = leftGroupsOrder.Length - 1;

            for (int i = 0; i < key.Length; i++)
            {
                if (lastLeftGroupsOrderIdx == 0)
                {
                    nextLeftGroupOrderIdx = 0;
                }
                else
                {
                    nextLeftGroupOrderIdx = random.Next(0, lastLeftGroupsOrderIdx);
                }

                nextGroupIdx = leftGroupsOrder[nextLeftGroupOrderIdx];
                lastCharIdx = charsLeftInGroup[nextGroupIdx] - 1;

                if (lastCharIdx == 0)
                {
                    nextCharIdx = 0;
                }
                else
                {
                    nextCharIdx = random.Next(0, lastCharIdx + 1);
                }

                key[i] = charGroups[nextGroupIdx][nextCharIdx];

                if (lastCharIdx == 0)
                {
                    charsLeftInGroup[nextGroupIdx] = charGroups[nextGroupIdx].Length;
                }
                else
                {
                    if (lastCharIdx != nextCharIdx)
                    {
                        char temp = charGroups[nextGroupIdx][lastCharIdx];

                        charGroups[nextGroupIdx][lastCharIdx] = charGroups[nextGroupIdx][nextGroupIdx];
                        charGroups[nextGroupIdx][nextGroupIdx] = temp;
                    }

                    charsLeftInGroup[nextGroupIdx]--;
                }

                if (lastLeftGroupsOrderIdx == 0)
                {
                    lastLeftGroupsOrderIdx = leftGroupsOrder.Length - 1;
                }
                else
                {
                    if (lastLeftGroupsOrderIdx != nextLeftGroupOrderIdx)
                    {
                        int temp = leftGroupsOrder[lastLeftGroupsOrderIdx];

                        leftGroupsOrder[lastLeftGroupsOrderIdx] = leftGroupsOrder[nextLeftGroupOrderIdx];
                        leftGroupsOrder[nextLeftGroupOrderIdx] = temp;
                    }

                    lastLeftGroupsOrderIdx--;
                }
            }

            return new string(key);
        }
    }
}