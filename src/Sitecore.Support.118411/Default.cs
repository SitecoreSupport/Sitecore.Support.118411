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

            bool flag = true;
            if (!string.IsNullOrEmpty(this.Context.Request.QueryString.ToString()) && Settings.GetSetting("ForceClientLanguageOnLogin") == "false")
            {
                flag = false;
            }

            UrlString urlString = new UrlString(text);
            if (string.IsNullOrEmpty(urlString["sc_lang"]) & flag)
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
            LoggingInArgs loggingInArgs = new LoggingInArgs
            {
                Username = this.fullUserName,
                Password = this.Password.Text,
                StartUrl = this.startUrl
            };
            
            Pipeline.Start("loggingin", loggingInArgs);
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
            if (Settings.Login.RememberLastLoggedInUserName)
            {
                Default.WriteCookie(WebUtil.GetLoginCookieName(), this.UserName.Text);
            }
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
        
        protected void LoginClicked(object sender, EventArgs e)
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
        
        protected override void OnInit(EventArgs e)
        {
            try
            {
                base.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
            }
            catch (PlatformNotSupportedException ex)
            {
                Log.Error("Setting response headers is not supported.", ex, this);
            }
            if (Sitecore.Context.User.IsAuthenticated)
            {
                if (WebUtil.GetQueryString("inv") == "1")
                {
                    Boost.Invalidate();
                }
                if (!DomainAccessGuard.GetAccess())
                {
                    base.Response.Redirect(WebUtil.GetFullUrl("/sitecore/client/Applications/LicenseOptions/StartPage"));
                    return;
                }
            }
            this.DataBind();
            if (Settings.Login.DisableRememberMe)
            {
                this.LoginForm.Attributes.Add("autocomplete", "off");
            }
            if (!base.IsPostBack && Settings.Login.RememberLastLoggedInUserName)
            {
                string cookieValue = WebUtil.GetCookieValue(WebUtil.GetLoginCookieName());
                if (!string.IsNullOrEmpty(cookieValue))
                {
                    MachineKeyEncryption.TryDecode(cookieValue, out cookieValue);
                    this.UserName.Text = cookieValue;
                    this.UserNameForgot.Text = cookieValue;
                }
            }
            try
            {
                base.Response.Headers.Add("SC-Login", "true");
            }
            catch (PlatformNotSupportedException ex2)
            {
                Log.Error("Setting response headers is not supported.", ex2, this);
            }
            this.RenderSdnInfoPage();
            base.OnInit(e);
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
