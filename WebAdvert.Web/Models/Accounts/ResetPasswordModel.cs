using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebAdvert.Web.Models.Accounts
{
    public class ResetPasswordModel
    {
        [Required(ErrorMessage ="Email is required!")]
        [EmailAddress]
        [Display(Name ="Email")]
        public string Email { get; set; }

        [Required(ErrorMessage ="Token is Required!")]    
        [Display(Name ="Token")]
        public string Token { get; set; }

        [Required(ErrorMessage = "New Password is Required!")]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; }


        [Required(ErrorMessage = "Confirm Password is Required!")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage ="Confirm new password must be same as new password!")]
        public string ConfirmNewPassword { get; set; }
    }
}
