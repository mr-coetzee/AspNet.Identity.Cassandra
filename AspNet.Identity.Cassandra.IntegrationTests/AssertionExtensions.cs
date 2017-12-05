using FluentAssertions;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Some fluent helper extensions for assertions.
    /// </summary>
    internal static class AssertionExtensions
    {
        /// <summary>
        /// Asserts that the user should have the same Id and UserName as the other user.
        /// </summary>
        public static void ShouldBeEquivalentToUser(this User user, User otherUser)
        {
            user.ShouldBeEquivalentTo(otherUser, opt => opt.Including(u => u.Id).Including(u => u.UserName));
        }
        /// <summary>
        /// Asserts that the user should have the same Id and UserName as the other user.
        /// </summary>
        public static void ShouldBeEquivalentToRole(this Role role, Role otherRole)
        {
            role.ShouldBeEquivalentTo(otherRole, opt => opt.Including(r => r.Id).Including(r => r.Name));
        }

        /// <summary>
        /// Asserts that the IdentityResult is a success.
        /// </summary>
        public static void ShouldBeSuccess(this IdentityResult result)
        {
            result.Succeeded.Should().BeTrue();
        }

        /// <summary>
        /// Asserts that the IdentityResult is a failure.
        /// </summary>
        public static void ShouldBeFailure(this IdentityResult result)
        {
            result.Succeeded.Should().BeFalse();
        }
    }
}
