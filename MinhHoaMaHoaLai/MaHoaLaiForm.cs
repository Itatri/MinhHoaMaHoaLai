using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MinhHoaMaHoaLai
{
    public partial class MaHoaLaiForm : Form
    {
        public MaHoaLaiForm()
        {
            InitializeComponent();
        }
        public class RSA
        {
            public int p { get; set; }
            public int q { get; set; }
            public int n { get; private set; }
            public int z { get; private set; }
            public int e { get; set; }
            public int d { get; private set; }

            public RSA(int p, int q)
            {
                this.p = p;
                this.q = q;
                this.n = p * q;
                this.z = (p - 1) * (q - 1);
                this.e = FindE();
                this.d = FindD();
            }

            // Tìm số e thỏa mãn gcd(e, z) = 1 và 1 < e < z
            private int FindE()
            {
                for (int i = 2; i < z; i++)
                {
                    if (GCD(i, z) == 1)
                        return i;
                }
                throw new InvalidOperationException("Không tìm thấy giá trị e hợp lệ.");
            }

            // Tìm số d thỏa mãn (e * d) mod z = 1
            private int FindD()
            {
                int x, y;
                ExtendedGCD(e, z, out x, out y);
                return (x % z + z) % z; // Đảm bảo d không âm
            }

            // Tính toán ước số chung lớn nhất (GCD)
            private int GCD(int a, int b)
            {
                while (b != 0)
                {
                    int temp = b;
                    b = a % b;
                    a = temp;
                }
                return a;
            }

            // Tính toán thuật toán Euclid mở rộng
            private int ExtendedGCD(int a, int b, out int x, out int y)
            {
                if (a == 0)
                {
                    x = 0;
                    y = 1;
                    return b;
                }
                int x1, y1;
                int gcd = ExtendedGCD(b % a, a, out x1, out y1);
                x = y1 - (b / a) * x1;
                y = x1;
                return gcd;
            }

            // Mã hóa dữ liệu
            public int Encrypt(int m)
            {
                return ModExp(m, e, n);
            }

            // Giải mã dữ liệu
            public int Decrypt(int c)
            {
                return ModExp(c, d, n);
            }

            // Tính toán m^e mod n
            private int ModExp(int baseVal, int exp, int mod)
            {
                int result = 1;
                while (exp > 0)
                {
                    if ((exp % 2) == 1)
                    {
                        result = (result * baseVal) % mod;
                    }
                    baseVal = (baseVal * baseVal) % mod;
                    exp /= 2;
                }
                return result;
            }
        }

        public class CaesarCipher
        {
            public int Key { get; set; }

            public CaesarCipher(int key)
            {
                Key = key;
            }

            public string Encrypt(string plainText)
            {
                StringBuilder encryptedText = new StringBuilder();
                foreach (char ch in plainText)
                {
                    if (char.IsLetter(ch))
                    {
                        char d = char.IsUpper(ch) ? 'A' : 'a';
                        int newIndex = (((ch - d) + Key) % 26);
                        encryptedText.Append((char)(newIndex + d));
                    }
                    else
                    {
                        encryptedText.Append(ch);
                    }
                }
                return encryptedText.ToString();
            }

            public string Decrypt(string cipherText)
            {
                StringBuilder decryptedText = new StringBuilder();
                foreach (char ch in cipherText)
                {
                    if (char.IsLetter(ch))
                    {
                        char d = char.IsUpper(ch) ? 'A' : 'a';
                        int newIndex = (((ch - d) - Key + 26) % 26);
                        decryptedText.Append((char)(newIndex + d));
                    }
                    else
                    {
                        decryptedText.Append(ch);
                    }
                }
                return decryptedText.ToString();
            }
        }


        private void btnEncrypt_Click(object sender, EventArgs e)
        {

            try
            {
                int p = int.Parse(txtP.Text);
                int q = int.Parse(txtQ.Text);
                int eValue = int.Parse(txtE.Text);
                int symmetricKey = int.Parse(txtSymmetricKey.Text);
                string plainText = txtPlainText.Text;

                // Khởi tạo thuật toán RSA
                RSA rsa = new RSA(p, q);
                rsa.e = eValue;

                // Mã hóa dữ liệu gốc bằng Caesar cipher
                CaesarCipher caesar = new CaesarCipher(symmetricKey);
                string encryptedText = caesar.Encrypt(plainText);

                // Mã hóa khóa đối xứng bằng RSA
                int encryptedSymmetricKey = rsa.Encrypt(symmetricKey);

                // Hiển thị dữ liệu mã hóa
                txtEncryptedText.Text = encryptedText; // Hiển thị dữ liệu mã hóa
                txtEncryptedKey.Text = encryptedSymmetricKey.ToString(); // Hiển thị khóa đối xứng mã hóa
            }
            catch (Exception ex)
            {
                MessageBox.Show("Có lỗi xảy ra: " + ex.Message);
            }

        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                int p = int.Parse(txtP.Text);
                int q = int.Parse(txtQ.Text);
                int eValue = int.Parse(txtE.Text);
                int encryptedSymmetricKey = int.Parse(txtEncryptedKey.Text); // Lấy khóa đối xứng mã hóa
                string encryptedText = txtEncryptedText.Text; // Lấy dữ liệu mã hóa

                // Khởi tạo thuật toán RSA
                RSA rsa = new RSA(p, q);
                rsa.e = eValue;

                // Giải mã khóa đối xứng từ RSA
                int decryptedSymmetricKey = rsa.Decrypt(encryptedSymmetricKey);

                // Sử dụng khóa đối xứng để giải mã dữ liệu
                CaesarCipher caesar = new CaesarCipher(decryptedSymmetricKey);
                string decryptedText = caesar.Decrypt(encryptedText);

                // Hiển thị dữ liệu đã giải mã
                txtDecryptedData.Text = decryptedText;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Có lỗi xảy ra: " + ex.Message);
            }
        }
    }
}
