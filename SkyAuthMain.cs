using System;
using System.Collections;
using System.EnterpriseServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace SkyAuthHandler
{
    [ClassInterface(ClassInterfaceType.AutoDual)]
    public class SkyAuthMain : ServicedComponent
    {
        private SkyAuthNonce SkyAuthNonce;

        public SkyAuthMain()
        {
            SkyAuthNonce = new SkyAuthNonce();
        }

        [STAThread]
        public string URLEncoding(string paramString)
        {
            string encodeString = "";

            if (paramString == "" || paramString == null)
                return encodeString;

            StringBuilder encodeStringBuilder = new StringBuilder();

            string unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            foreach (Char symbol in paramString)
            {
                if (unreservedChars.IndexOf(symbol) != -1)
                {
                    encodeStringBuilder.Append(symbol);
                }
                else
                {
                    encodeStringBuilder.Append("%" + String.Format("{0:X2}", Convert.ToInt32(symbol)));
                }
            }

            encodeString = encodeStringBuilder.ToString();

            return encodeString;
        }

        [STAThread]
        public string ConvertUTF8(string paramString)
        {
            string convertString = "";

            if (paramString == "" || paramString == null)
                return convertString;

            Encoding utf8 = Encoding.UTF8;
            byte[] utf8Bytes = utf8.GetBytes(paramString);

            foreach (byte b in utf8Bytes)
            {
                string.Format("{0:x}", b);
            }

            return utf8.GetString(utf8Bytes);
        }

        [STAThread]
        public string CreateNonce(string lengthText)
        {
            string auth_nonce = "";
            int length = 0;

            if (lengthText.Length > 0)
            {
                try
                {
                    length = Convert.ToInt32(lengthText);
                }
                catch { }
            }

            if (length > 0)
                auth_nonce = SkyAuthNonce.Generate(length);
            else
                auth_nonce = SkyAuthNonce.Generate();

            return auth_nonce;
        }

        [STAThread]
        public string CreateTimestamp()
        {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);

            string timestamp = Convert.ToInt64(ts.TotalSeconds).ToString();

            return timestamp;
        }

        [STAThread]
        public string CreateSignature(
                                    string param_http_method, 
                                    string param_request_url, 
                                    string param_consumer_key,
                                    string param_consumer_secret,
                                    string param_token_secret,
                                    string param_info)
        {
            string oauth_signature = "";
            string oauth_parameter1 = "";
            string oauth_parameter2 = "";
            string oauth_parameter3 = "";
            string oauth_baseString = "";

            char[] param_split1 = new char[] { '&' };
            char[] param_split2 = new char[] { '=' };

            string link_word = "&";
            string equal_word = "=";

            if (param_http_method == "" || param_http_method == null)
            {
                param_http_method = "GET";
            }

            if (param_request_url == "" || param_request_url == null)
            {
                return oauth_signature;
            }

            if (param_consumer_key == "" || param_consumer_key == null)
            {
                return oauth_signature;
            }

            if (param_consumer_secret == "" || param_consumer_secret == null)
            {
                return oauth_signature;
            }

            if (param_info == "" || param_info == null)
            {
                return oauth_signature;
            }

            string[] param_info_array1 = param_info.Split(param_split1);
            int param_len = param_info_array1.Length;

            string[] param_key_array = new string[param_len];
            string[] param_value_array = new string[param_len];

            for (int i = 0; i < param_len; i++)
            {
                string tmp_info = param_info_array1[i];

                string[] param_info_array2 = tmp_info.Split(param_split2);

                param_key_array[i] = param_info_array2[0];
                param_value_array[i] = param_info_array2[1];
            }

            oauth_parameter1 = param_http_method + link_word + URLEncoding(param_request_url) + link_word;

            for (int j = 0; j < param_len; j++)
            {
                oauth_parameter2 += param_key_array[j];
                oauth_parameter2 += equal_word;
                oauth_parameter2 += param_value_array[j];

                if ((j + 1) < param_len)
                {
                    oauth_parameter2 += link_word;
                }
            }

            if (param_token_secret.Length > 0)
            {
                oauth_parameter3 = URLEncoding(param_consumer_secret) + link_word + URLEncoding(param_token_secret);

                //oauth_baseString = oauth_parameter1 + Base64Encode(oauth_parameter2);
            }
            else
            {
                oauth_parameter3 = URLEncoding(param_consumer_secret) + link_word;

                //oauth_baseString = oauth_parameter1 + URLEncoding(oauth_parameter2);
            }

            oauth_baseString = oauth_parameter1 + URLEncoding(oauth_parameter2);

            oauth_signature = HmacSha1Encrypt(oauth_parameter3, oauth_baseString);

            return URLEncoding(oauth_signature);
        }

        [STAThread]
        public string CreateSignature2(
                                    string param_http_method,
                                    string param_request_url,
                                    string param_consumer_key,
                                    string param_consumer_secret,
                                    string param_token_secret,
                                    string param_info)
        {
            string oauth_signature = "";
            string oauth_parameter1 = "";
            string oauth_parameter2 = "";
            string oauth_baseString = "";

            char[] param_split1 = new char[] { '&' };
            char[] param_split2 = new char[] { '=' };

            string link_word = "&";
            string equal_word = "=";

            if (param_http_method == "" || param_http_method == null)
            {
                param_http_method = "GET";
            }

            if (param_request_url == "" || param_request_url == null)
            {
                return oauth_signature;
            }

            if (param_consumer_key == "" || param_consumer_key == null)
            {
                return oauth_signature;
            }

            if (param_consumer_secret == "" || param_consumer_secret == null)
            {
                return oauth_signature;
            }

            if (param_info == "" || param_info == null)
            {
                return oauth_signature;
            }

            string[] param_info_array1 = param_info.Split(param_split1);
            int param_len = param_info_array1.Length;

            string[] param_key_array = new string[param_len];
            string[] param_value_array = new string[param_len];

            for (int i = 0; i < param_len; i++)
            {
                string tmp_info = param_info_array1[i];

                string[] param_info_array2 = tmp_info.Split(param_split2);

                param_key_array[i] = param_info_array2[0];
                param_value_array[i] = param_info_array2[1];
            }

            oauth_parameter1 = param_http_method + link_word + URLEncoding(param_request_url) + link_word;

            for (int j = 0; j < param_len; j++)
            {
                oauth_parameter2 += param_key_array[j];
                oauth_parameter2 += equal_word;
                oauth_parameter2 += param_value_array[j];

                if ((j + 1) < param_len)
                {
                    oauth_parameter2 += link_word;
                }
            }

            HMACSHA1 sha1 = new HMACSHA1();

            sha1.Key = Encoding.ASCII.GetBytes(URLEncoding(param_consumer_secret) + link_word + (string.IsNullOrEmpty(param_token_secret) ? "" : URLEncoding(param_token_secret)));

            return Convert.ToBase64String(sha1.ComputeHash(Encoding.ASCII.GetBytes(oauth_baseString)));
        }

        [STAThread]
        private string HmacSha1Encrypt(string encryptKey, string plainString)
        {
            string encryptString = "";

            if (encryptKey == "" || encryptKey == null)
                return encryptString;

            if (plainString == "" || plainString == null)
                return encryptString;

            byte[] keyByte = Encoding.UTF8.GetBytes(encryptKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainString);

            HMACSHA1 hmacsha1 = new HMACSHA1(keyByte);

            byte[] plainHash = hmacsha1.ComputeHash(plainBytes);

            encryptString = Convert.ToBase64String(plainHash);

            return encryptString;
        }

        [STAThread]
        private string Base64Encode(string plainString)
        {
            byte[] toEncodeAsBytes = ASCIIEncoding.ASCII.GetBytes(plainString);

            string encodeString = Convert.ToBase64String(toEncodeAsBytes);

            return encodeString;
        }

        [STAThread]
        private string Base64Decode(string encodeString)
        {
            byte[] encodeDataAsBytes = Convert.FromBase64String(encodeString);

            string decodeString = ASCIIEncoding.ASCII.GetString(encodeDataAsBytes);

            return decodeString;
        }

        [STAThread]
        private string ByteToString(byte[] buff)
        {
            string byteString = "";

            for (int i = 0; i < buff.Length; i++)
            {
                byteString += buff[i].ToString("X2");
            }

            return byteString;
        }
    }
}
