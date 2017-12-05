using System;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests for basic role CRUD.
    /// </summary>
    [TestFixture]
    public class RolesCrudTests : IntegrationTestBase
    {
        [Test]
        public async void CreateRole()
        {
            // Create role
            var originalRole = new Role(Guid.NewGuid()) { Name = "testRole1" };
            IdentityResult result = await RoleManager.CreateAsync(originalRole);
            result.ShouldBeSuccess();

            // Try to find roles by id and rolename
            Role foundRole = await RoleManager.FindByIdAsync(originalRole.Id);
            foundRole.ShouldBeEquivalentToRole(originalRole);

            foundRole = await RoleManager.FindByNameAsync(originalRole.Name);
            foundRole.ShouldBeEquivalentToRole(originalRole);
        }

        [Test]
        public async void ChangeRolename()
        {
            // Create role, then lookup by Id
            var originalRole = new Role(Guid.NewGuid()) { Name = "originalName" };
            await RoleManager.CreateAsync(originalRole);
            Role foundRole = await RoleManager.FindByIdAsync(originalRole.Id);
            
            // Change the rolename and update
            const string newName = "testRole2";
            foundRole.Name = newName;
            IdentityResult result = await RoleManager.UpdateAsync(foundRole);
            result.ShouldBeSuccess();

            // Should not be able to find them by the old rolename
            foundRole = await RoleManager.FindByNameAsync(originalRole.Name);
            foundRole.Should().BeNull();

            // Should still be able to find by id and new rolename
            foundRole = await RoleManager.FindByIdAsync(originalRole.Id);
            foundRole.Should().NotBeNull();
            foundRole.Name.Should().Be(newName);

            foundRole = await RoleManager.FindByNameAsync(newName);
            foundRole.Should().NotBeNull();
            foundRole.Id.Should().Be(originalRole.Id);
        }

        [Test]
        public async void DeleteRole()
        {
            // Create role, then lookup by Id
            var originalRole = new Role(Guid.NewGuid()) { Name = "deletedRole" };
            await RoleManager.CreateAsync(originalRole);
            Role foundRole = await RoleManager.FindByIdAsync(originalRole.Id);
            
            // Delete the role
            IdentityResult result = await RoleManager.DeleteAsync(foundRole);
            result.ShouldBeSuccess();

            // Should not be able to find by id or rolename
            foundRole = await RoleManager.FindByIdAsync(originalRole.Id);
            foundRole.Should().BeNull();

            foundRole = await RoleManager.FindByNameAsync(originalRole.Name);
            foundRole.Should().BeNull();
        }
    }
}
