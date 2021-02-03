using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Cryptography;
using System.Text;
using System.Data;
using System.Data.SqlClient;
using System.Text.RegularExpressions;
using System.Drawing;
using System.Configuration;

namespace AS_PracAssignment
{
    public partial class Registration : System.Web.UI.Page
    {
        string MYDBConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["MYDBConnection"].ConnectionString;
        static string finalHash;
        static string salt;
        byte[] Key;
        byte[] IV;
        protected void Page_Load(object sender, EventArgs e)
        {
          
        }

        protected void btnRegister(object sender, EventArgs e)
        {
            if (InputValidation())
            {
                if (getEmail(tb_email.Text.Trim()) == null)
                {

                    //string pwd = get value from your Textbox
                    string pwd = tb_password.Text.ToString().Trim(); ;
                    //Generate random "salt"
                    RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                    byte[] saltByte = new byte[8];
                    //Fills array of bytes with a cryptographically strong sequence of random values.
                    rng.GetBytes(saltByte);
                    salt = Convert.ToBase64String(saltByte);
                    SHA512Managed hashing = new SHA512Managed();
                    string pwdWithSalt = pwd + salt;
                    byte[] plainHash = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwd));
                    byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                    finalHash = Convert.ToBase64String(hashWithSalt);
                    RijndaelManaged cipher = new RijndaelManaged();
                    cipher.GenerateKey();
                    Key = cipher.Key;
                    IV = cipher.IV;

                    int noCheck = checkPassword(tb_password.Text.ToString());

                    if (noCheck < 5)
                    {
                        errorMsg.Text = "Password is too weak. Please use a different password";
                        errorMsg.ForeColor = Color.Red;
                    }
                    else
                    {
                        createAccount();
                        errorMsg.Text = "";
                        Response.Redirect("Login.aspx");
                    }
                }
                else
                {
                    errorMsg.Text = "Email already exists!";
                    errorMsg.ForeColor = Color.Red;
                }

            }
            
        }

        protected void createAccount()
        {
            string Fname = HttpUtility.HtmlEncode(tb_fname.Text.Trim());
            string Lname = HttpUtility.HtmlEncode(tb_lname.Text.Trim());
            string CC = HttpUtility.HtmlEncode(tb_cc.Text.Trim());
            string dob = HttpUtility.HtmlEncode(tb_dob.Text.Trim());
            string email = HttpUtility.HtmlEncode(tb_email.Text.Trim());

            try
            {
                using (SqlConnection con = new SqlConnection(MYDBConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Account VALUES(@Fname, @Lname, @CC, @PasswordHash, @PasswordSalt, @DOB, @IV, @Key, @EmailVerified, @Email, @DateTimeRegistered, @AccountLockout, @TimeOfLogin, @TimeOfPwdChange)"))
                    {
                        using (SqlDataAdapter sda = new SqlDataAdapter())
                        {
                            cmd.CommandType = CommandType.Text;                           
                            cmd.Parameters.AddWithValue("@Fname", Fname);
                            cmd.Parameters.AddWithValue("@Lname", Lname);
                            cmd.Parameters.AddWithValue("@CC", Convert.ToBase64String(encryptData(CC)));
                            cmd.Parameters.AddWithValue("@PasswordHash", finalHash);
                            cmd.Parameters.AddWithValue("@PasswordSalt", salt);
                            cmd.Parameters.AddWithValue("@DOB", dob);
                            cmd.Parameters.AddWithValue("@IV", Convert.ToBase64String(IV));
                            cmd.Parameters.AddWithValue("@Key", Convert.ToBase64String(Key));
                            cmd.Parameters.AddWithValue("@EmailVerified", DBNull.Value);
                            cmd.Parameters.AddWithValue("@Email", email);
                            cmd.Parameters.AddWithValue("@DateTimeRegistered", DateTime.Now.ToString());
                            cmd.Parameters.AddWithValue("@AccountLockout", 0);
                            cmd.Parameters.AddWithValue("@TimeOfLogin", "");
                            cmd.Parameters.AddWithValue("@TimeOfPwdChange", "");
                            cmd.Connection = con;
                            con.Open();
                            cmd.ExecuteNonQuery();
                            con.Close();
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
        }

        protected byte[] encryptData(string data)
        {
            byte[] cipherText = null;
            try
            {
                RijndaelManaged cipher = new RijndaelManaged();
                cipher.IV = IV;
                cipher.Key = Key;
                ICryptoTransform encryptTransform = cipher.CreateEncryptor();
                //ICryptoTransform decryptTransform = cipher.CreateDecryptor();
                byte[] plainText = Encoding.UTF8.GetBytes(data);
                cipherText = encryptTransform.TransformFinalBlock(plainText, 0, plainText.Length);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { }
            return cipherText;
        }

        protected string getEmail(string email)
        {
            string ge = null;
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "select Email FROM Account WHERE Email=@Email";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@Email", email);
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {

                    while (reader.Read())
                    {
                        if (reader["Email"] != null)
                        {
                            if (reader["Email"] != DBNull.Value)
                            {
                                ge = reader["Email"].ToString();
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return ge;
        }

        private int checkPassword(string password)
        {
            int score = 0;

            //Score 1 very weak!
            //if length of password is less than 8 chars
            if (password.Length < 8)
            {
                return 1;
            }
            else
            {
                score = 1;
            }

            if (Regex.IsMatch(password, "[a-z]"))
            {
                score++;
            }

            if (Regex.IsMatch(password, "[A-Z]"))
            {
                score++;
            }

            if (Regex.IsMatch(password, "[0-9]"))
            {
                score++;
            }

            if (Regex.IsMatch(password, "^[a-zA-Z0-9 ]*$"))
            {
                return score;
            }
            else
            {
                score++;
            }


            return score;
        }

        protected void chk_Pwd(object sender, EventArgs e)
        {
            int scores = checkPassword(tb_password.Text);
            string status = "";
            switch (scores)
            {
                case 1:
                    status = "Very Weak";
                    break;
                case 2:
                    status = "Weak";
                    break;
                case 3:
                    status = "Medium";
                    break;
                case 4:
                    status = "Strong";
                    break;
                case 5:
                    status = "Excellent";
                    break;
                default:
                    break;
            }

            lb_pwdStrength.Text = "Status : " + status;
            if (scores < 4)
            {
                lb_pwdStrength.ForeColor = Color.Red;
                return;
            }
            lb_pwdStrength.ForeColor = Color.Green;
        }

        private bool InputValidation()
        {
            errorMsg.Text = "";
            errorMsg.ForeColor = Color.Red;
            if (tb_email.Text == "")
            {
                errorMsg.Visible = true;
                errorMsg.Text += "Email is required!" + "<br/>";
            }
            string emp = getEmail(tb_email.Text);
            if (emp != null)
            {
                errorMsg.Visible = true;
                errorMsg.Text += "Email already exists!" + "<br/>";
            }
            if (String.IsNullOrEmpty(tb_fname.Text))
            {
                errorMsg.Visible = true;
                errorMsg.Text += "First Name is required!" + "<br/>";
            }
            if (String.IsNullOrEmpty(tb_lname.Text))
            {
                errorMsg.Visible = true;
                errorMsg.Text += "Last name is required!" + "<br/>";
            }
            if (String.IsNullOrEmpty(tb_cc.Text))
            {
                errorMsg.Visible = true;
                errorMsg.Text += "Credit Card is required!" + "<br/>";
            }
            if (String.IsNullOrEmpty(tb_dob.Text))
            {
                errorMsg.Visible = true;
                errorMsg.Text += "Date of Birth is required!" + "<br/>";
            }
            if (String.IsNullOrEmpty(tb_password.Text))
            {
                errorMsg.Visible = true;
                errorMsg.Text += "Password is required!" + "<br/>";
            }
            if (String.IsNullOrEmpty(tb_pwdConfirm.Text))
            {
                errorMsg.Visible = true;
                errorMsg.Text += "Please confirm your password!" + "<br/>";
            }
            if (tb_password.Text.ToString() != tb_pwdConfirm.Text.ToString())
            {
                errorMsg.Text += "Password does not match! Please try again!" + "<br/>";
            }
            if (String.IsNullOrEmpty(errorMsg.Text))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}