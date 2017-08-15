using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Globalization;
using Sitecore.Pipelines;
using Sitecore.Pipelines.LoggedIn;
using Sitecore.Pipelines.LoggingIn;
using Sitecore.Security.Accounts;
using Sitecore.SecurityModel.Cryptography;
using Sitecore.SecurityModel.License;
using Sitecore.Text;
using Sitecore.Web;
using Sitecore.Web.Authentication;
using Sitecore.Security.Authentication;
using System.Text.RegularExpressions;
using System;
using System.Web;

namespace Sitecore.Support.sitecore.login
{
    public class Default : Sitecore.sitecore.login.Default
    {
        private string fullUserName = string.Empty;
        private string startUrl = string.Empty;

        protected override void LoggedIn()
        {
            User user = Sitecore.Security.Accounts.User.FromName(this.fullUserName, false);
            State.Client.UsesBrowserWindows = true;
            LoggedInArgs loggedInArgs = new LoggedInArgs
            {
                Username = this.fullUserName,
                StartUrl = this.startUrl,
                Persist = this.ShouldPersist()
            };

            Pipeline.Start("loggedin", loggedInArgs);
            string text = loggedInArgs.StartUrl;
            string @string = StringUtil.GetString(new string[]
            {
                user.Profile.ClientLanguage,
                Settings.ClientLanguage
            });

            /*
                ALEX20170815:
                Query string "sc_lang" has caused the issue by redirecting user to the page following their ClientLanguage setting even though the URL contains different language.
                This solution is to prevent adding the query string "sc_lang".
                    e.g. <sitecoreInstance>/ja-jp?sc_mode=edit   <-- (don't add the "sc_lang" query string here)

                "ForceClientLanguageOnLogin" setting is added by this patch with "false" value to prevent using the ClientLanguage.
            */
            bool flag = true;
            if (!string.IsNullOrEmpty(this.Context.Request.QueryString.ToString()) && Settings.GetSetting("ForceClientLanguageOnLogin") == "false")
            {
                flag = false;
            }

            UrlString urlString = new UrlString(text);
            if (string.IsNullOrEmpty(urlString["sc_lang"]) && flag)
            {
                urlString["sc_lang"] = @string;
            }
            this.startUrl = urlString.ToString();
            using (new UserSwitcher(user))
            {
                Log.Audit(this, "Login", new string[0]);
            }
        }
        
        protected override bool LoggingIn()
        {
            if (string.IsNullOrWhiteSpace(this.UserName.Text))
            {
                return false;
            }
            this.fullUserName = WebUtil.HandleFullUserName(this.UserName.Text);
            this.startUrl = WebUtil.GetQueryString("returnUrl");
            this.FailureHolder.Visible = false;
            this.SuccessHolder.Visible = false;

            if (Settings.Login.RememberLastLoggedInUserName)
            {
                Default.WriteCookie(WebUtil.GetLoginCookieName(), this.UserName.Text);
            }

            LoggingInArgs loggingInArgs = new LoggingInArgs
            {
                Username = this.fullUserName,
                Password = this.Password.Text,
                StartUrl = this.startUrl
            };
            Pipeline.Start("loggingin", loggingInArgs);
            bool flag = UIUtil.IsIE() || UIUtil.IsIE11();
            if (flag && !Regex.IsMatch(WebUtil.GetHostName(), Settings.HostNameValidationPattern, RegexOptions.ECMAScript))
            {
                this.RenderError(Translate.Text("Your login attempt was not successful because the URL hostname contains invalid character(s) that are not recognized by IE. Please check the URL hostname or try another browser."));
                return false;
            }
            if (!loggingInArgs.Success)
            {
                Log.Audit(string.Format("Login failed: {0}.", loggingInArgs.Username), this);
                if (!string.IsNullOrEmpty(loggingInArgs.Message))
                {
                    this.RenderError(Translate.Text(StringUtil.RemoveLineFeeds(loggingInArgs.Message)));
                }
                return false;
            }
            this.startUrl = loggingInArgs.StartUrl;
            return true;
        }
        
        protected override bool Login()
        {
            if (AuthenticationManager.Login(this.fullUserName, this.Password.Text, this.ShouldPersist()))
            {
                return true;
            }
            this.RenderError("Your login attempt was not successful. Please try again.");
            return false;
        }
        
        protected new void LoginClicked(object sender, EventArgs e)
        {
            if (!this.LoggingIn())
            {
                return;
            }
            if (!this.Login())
            {
                return;
            }
            this.LoggedIn();
            this.CheckDomainGuard();
            WebUtil.Redirect(this.startUrl);
        }

        private void LogMaxEditorsExceeded()
        {
            string format = "The maximum number of simultaneously active (logged-in) editors exceeded. The User {0} cannot be logged in to the system. The maximum of editors allowed by license is {1}.";
            Log.Warn(string.Format(format, this.fullUserName, DomainAccessGuard.MaximumSessions), this);
        }
        
        private static void WriteCookie(string name, string value)
        {
            Assert.ArgumentNotNull(name, "name");
            Assert.ArgumentNotNull(value, "value");
            if (name == WebUtil.GetLoginCookieName())
            {
                value = MachineKeyEncryption.Encode(value);
            }
            HttpCookie cookie = new HttpCookie(name, value)
            {
                Expires = DateTime.UtcNow.AddMonths(3),
                Path = "/sitecore/login",
            };
            HttpContext.Current.Response.AppendCookie(cookie);
            HttpCookie httpCookie = HttpContext.Current.Request.Cookies[name];
            if (httpCookie != null)
            {
                httpCookie.Value = value;
            }
        }

        private void CheckDomainGuard()
        {
            if (!DomainAccessGuard.GetAccess())
            {
                this.startUrl = WebUtil.GetFullUrl("/sitecore/client/Applications/LicenseOptions/StartPage");
            }
        }

        private void RenderSdnInfoPage()
        {
            UrlString urlString = new UrlString(Settings.Login.SitecoreUrl);
            urlString["id"] = License.LicenseID;
            urlString["host"] = WebUtil.GetHostName();
            urlString["licensee"] = License.Licensee;
            urlString["iisname"] = WebUtil.GetIISName();
            urlString["st"] = WebUtil.GetCookieValue("sitecore_starttab", string.Empty);
            urlString["sc_lang"] = Sitecore.Context.Language.Name;
            urlString["v"] = About.GetVersionNumber(true);
            this.StartPage.Attributes["src"] = urlString.ToString();
            this.StartPage.Attributes["onload"] = "javascript:this.style.display='block'";
        }
                
        private void RenderError(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            this.FailureHolder.Visible = true;
            this.FailureText.Text = text;
        }
        
        private void RenderSuccess(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            this.SuccessHolder.Visible = true;
            this.SuccessText.Text = text;
        }
        
        private bool ShouldPersist()
        {
            return !Settings.Login.DisableRememberMe && this.RememberMe.Checked;
        }
        
    }
}
