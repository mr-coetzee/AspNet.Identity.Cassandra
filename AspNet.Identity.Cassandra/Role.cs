using System;
using Cassandra;
using Microsoft.AspNetCore.Identity;

namespace AspNet.Identity.Cassandra
{
    /// <summary>
    /// Represents a.
    /// </summary>
    public class Role : IUserRole<Guid>
    {
        private readonly string _originalName;

        /// <summary>
        /// The unique Id of the role.
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// The role name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The description.
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Default constructor with NewGuid
        /// </summary>
        public Role()
            : this(Guid.NewGuid(), null, null)
        {
        }

        /// <summary>
        /// Creates a new role with the Id specified.
        /// </summary>
        public Role(Guid id)
            : this(id, null, null)
        {
        }

        private Role(Guid id, string name, string description)
        {
            Id = id;
            Name = name;
            Description = description;

            _originalName = name;
        }
        
        /// <summary>
        /// Indicates whether the Name for the user has changed from the original Name used when the Role was
        /// created/loaded from C*.  Returns the original Name in an out parameter if true.
        /// </summary>
        internal bool HasNameChanged(out string originalName)
        {
            originalName = _originalName;
            return Name != _originalName;
        }

        /// <summary>
        /// Creates a Role from a Row.  If the Row is null, returns null.
        /// </summary>
        internal static Role FromRow(Row row)
        {
            if (row == null) return null;

            return new Role(row.GetValue<Guid>("id"), row.GetValue<string>("name"), row.GetValue<string>("description"));
        }
    }
}
