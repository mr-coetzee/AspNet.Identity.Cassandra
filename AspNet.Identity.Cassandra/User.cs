﻿using System;
using Cassandra;

namespace AspNet.Identity.Cassandra
{
    /// <summary>
    /// Represents a user.
    /// </summary>
    public class User
    {
        private readonly string _originalUserName;
        private readonly string _originalEmail;
        
        /// <summary>
        /// The unique Id of the user.
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// The user's username.
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// The password hash for the user.
        /// </summary>
        public string PasswordHash { get; set; }

        /// <summary>
        /// The security stamp for the user.
        /// </summary>
        public string SecurityStamp { get; set; }

        /// <summary>
        /// Whether or not two factor authentication is enabled for the user.
        /// </summary>
        public bool IsTwoFactorEnabled { get; set; }

        /// <summary>
        /// The number of times the user has tried and failed to login.
        /// </summary>
        public int AccessFailedCount { get; set; }

        /// <summary>
        /// Whether or not lockout is enabled for the user.
        /// </summary>
        public bool IsLockoutEnabled { get; set; }

        /// <summary>
        /// When the user's lockout period will end.
        /// </summary>
        public DateTimeOffset LockoutEndDate { get; set; }

        /// <summary>
        /// The user's phone number.
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Whether the user's phone number has been confirmed.
        /// </summary>
        public bool IsPhoneNumberConfirmed { get; set; }

        /// <summary>
        /// The user's email address.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Whether the user's email address has been confirmed.
        /// </summary>
        public bool IsEmailConfirmed { get; set; }

        /// <summary>
        /// Default constructor with NewGuid
        /// </summary>
        public User()
            : this(Guid.NewGuid(), null, null)
        {
        }

        /// <summary>
        /// Creates a new CassandraUser with the Id specified.
        /// </summary>
        public User(Guid userId)
            : this(userId, null, null)
        {
        }

        private User(Guid userId, string userName, string email)
        {
            Id = userId;
            UserName = userName;
            Email = email;

            // Track the original username and email from when the object is created so we can tell if it changes
            _originalUserName = userName;
            _originalEmail = email;
        }

        /// <summary>
        /// Indicates whether the username for the user has changed from the original username used when the CassandraUser was
        /// created/loaded from C*.  Returns the original username in an out parameter if true.
        /// </summary>
        internal bool HasUserNameChanged(out string originalUserName)
        {
            originalUserName = _originalUserName;
            return UserName != _originalUserName;
        }

        /// <summary>
        /// Indicates whether the email address for the user has changed from the original email used when the CassandraUser was
        /// created/loaded from C*.  Returns the original email in an out parameter if true.
        /// </summary>
        internal bool HasEmailChanged(out string originalEmail)
        {
            originalEmail = _originalEmail;
            return Email != _originalEmail;
        }

        /// <summary>
        /// Creates a CassandraUser from a Row.  If the Row is null, returns null.
        /// </summary>
        internal static User FromRow(Row row)
        {
            if (row == null) return null;

            var user = new User(row.GetValue<Guid>("id"), row.GetValue<string>("username"), row.GetValue<string>("email"))
            {
                PasswordHash = row.GetValue<string>("password_hash"),
                SecurityStamp = row.GetValue<string>("security_stamp"),
                IsTwoFactorEnabled = row.GetValue<bool>("two_factor_enabled"),
                AccessFailedCount = row.GetValue<int>("access_failed_count"),
                IsLockoutEnabled = row.GetValue<bool>("lockout_enabled"),
                LockoutEndDate = row.GetValue<DateTimeOffset>("lockout_end_date"),
                PhoneNumber = row.GetValue<string>("phone_number"),
                IsPhoneNumberConfirmed = row.GetValue<bool>("phone_number_confirmed"),
                IsEmailConfirmed = row.GetValue<bool>("email_confirmed")
            };

            return user;
        }
    }
}
