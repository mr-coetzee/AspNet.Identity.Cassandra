using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Cassandra;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra
{
    public class RoleStore : IRoleStore<Role, Guid>
    {
        // A cached copy of some completed tasks
        private static readonly Task<bool> TrueTask = Task.FromResult(true);
        private static readonly Task<bool> FalseTask = Task.FromResult(false);
        private static readonly Task CompletedTask = TrueTask;

        private readonly ISession _session;
        private readonly bool _disposeOfSession;

        // Reusable prepared statements, lazy evaluated
        private readonly AsyncLazy<PreparedStatement[]> _createRole;
        private readonly AsyncLazy<PreparedStatement> _createRoleByname;
        private readonly AsyncLazy<PreparedStatement[]> _updateRole;
        private readonly AsyncLazy<PreparedStatement[]> _deleteRole;
        private readonly AsyncLazy<PreparedStatement> _deleteRoleByname;

        private readonly AsyncLazy<PreparedStatement> _findById;
        private readonly AsyncLazy<PreparedStatement> _findByName;
        
        /// <summary>
        /// Creates a new instance of CassandraRoleStore that will use the provided ISession instance to talk to Cassandra.  Optionally,
        /// specify whether the ISession instance should be Disposed when this class is Disposed.
        /// </summary>
        /// <param name="session">The session for talking to the Cassandra keyspace.</param>
        /// <param name="disposeOfSession">Whether to dispose of the session instance when this object is disposed.</param>
        /// <param name="createSchema">Whether to create the schema tables if they don't exist.</param>
        public RoleStore(ISession session, bool disposeOfSession = false, bool createSchema = true)
        {
            _session = session;
            _disposeOfSession = disposeOfSession;

            // Create some reusable prepared statements so we pay the cost of preparing once, then bind multiple times
            _createRoleByname = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync(
                "INSERT INTO Roles_by_name (name, id, description) " +
                "VALUES (?, ?, ?)"));

            _deleteRoleByname = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync("DELETE FROM Roles_by_name WHERE name = ?"));
            
            // All the statements needed by the CreateAsync method
            _createRole = new AsyncLazy<PreparedStatement[]>(() => Task.WhenAll(new []
            {
                _session.PrepareAsync("INSERT INTO Roles (id, name, description) " +
                                      "VALUES (?, ?, ?)"),
                _createRoleByname.Value,
            }));

            // All the statements needed by the DeleteAsync method
            _deleteRole = new AsyncLazy<PreparedStatement[]>(() => Task.WhenAll(new[]
            {
                _session.PrepareAsync("DELETE FROM Roles WHERE id = ?"),
                _deleteRoleByname.Value,
            }));

            // All the statements needed by the UpdateAsync method
            _updateRole = new AsyncLazy<PreparedStatement[]>(() => Task.WhenAll(new []
            {
                _session.PrepareAsync("UPDATE Roles SET name = ?, description = ? " +
                                      "WHERE id = ?"),
                _session.PrepareAsync("UPDATE Roles_by_name SET description = ? " +
                                      "WHERE name = ?"),
                _deleteRoleByname.Value,
                _createRoleByname.Value,
            }));
            
            _findById = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync("SELECT * FROM Roles WHERE id = ?"));
            _findByName = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync("SELECT * FROM Roles_by_name WHERE name = ?"));
            
            // Create the schema if necessary
            if (createSchema)
                SchemaCreationHelper.CreateSchemaIfNotExists(session);
        }

        /// <summary>
        /// Insert a new Role.
        /// </summary>
        public async Task CreateAsync(Role role)
        {
            if (role == null) throw new ArgumentNullException("Role");

            // TODO:  Support uniqueness for names/emails at the C* level using LWT?

            PreparedStatement[] prepared = await _createRole;
            var batch = new BatchStatement();

            // INSERT INTO Roles ...
            batch.Add(prepared[0].Bind(role.Id, role.Name, role.Description));

            // Only insert into name table if there is a value
            if (string.IsNullOrEmpty(role.Name) == false)
            {
                // INSERT INTO Roles_by_name ...
                batch.Add(prepared[1].Bind(role.Name, role.Id, role.Description));
            }
            
            await _session.ExecuteAsync(batch).ConfigureAwait(false);
        }

        /// <summary>
        /// Update a Role.
        /// </summary>
        public async Task UpdateAsync(Role role)
        {
            if (role == null) throw new ArgumentNullException("Role");

            PreparedStatement[] prepared = await _updateRole;
            var batch = new BatchStatement();

            // UPDATE Roles ...
            batch.Add(prepared[0].Bind(role.Name, role.Description, role.Id));

            // See if the name changed so we can decide whether we need a different Roles_by_name record
            string oldname;
            if (role.HasNameChanged(out oldname) == false && string.IsNullOrEmpty(role.Name) == false)
            {
                // UPDATE Roles_by_name ... (since name hasn't changed)
                batch.Add(prepared[1].Bind(role.Description, role.Name));
            }
            else
            {
                // DELETE FROM Roles_by_name ... (delete old record since name changed)
                if (string.IsNullOrEmpty(oldname) == false)
                {
                    batch.Add(prepared[2].Bind(oldname));
                }

                // INSERT INTO Roles_by_name ... (insert new record since name changed)
                if (string.IsNullOrEmpty(role.Name) == false)
                {
                    batch.Add(prepared[3].Bind(role.Name, role.Id, role.Description));
                }
            }
            
            await _session.ExecuteAsync(batch).ConfigureAwait(false);
        }

        /// <summary>
        /// Delete a Role.
        /// </summary>
        public async Task DeleteAsync(Role Role)
        {
            if (Role == null) throw new ArgumentNullException("Role");

            PreparedStatement[] prepared = await _deleteRole;
            var batch = new BatchStatement();

            // DELETE FROM Roles ...
            batch.Add(prepared[0].Bind(Role.Id));

            // Make sure the name didn't change before deleting from Roles_by_name (not sure this is possible, but protect ourselves anyway)
            string name;
            if (Role.HasNameChanged(out name) == false)
                name = Role.Name;

            // DELETE FROM Roles_by_name ...
            if (string.IsNullOrEmpty(name) == false)
                batch.Add(prepared[1].Bind(name));
            
            await _session.ExecuteAsync(batch).ConfigureAwait(false);
        }

        /// <summary>
        /// Finds a Role by id.
        /// </summary>
        public async Task<Role> FindByIdAsync(Guid id)
        {
            PreparedStatement prepared = await _findById;
            BoundStatement bound = prepared.Bind(id);

            RowSet rows = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            return Role.FromRow(rows.SingleOrDefault());
        }

        /// <summary>
        /// Find a Role by name (assumes names are unique).
        /// </summary>
        public async Task<Role> FindByNameAsync(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("name cannot be null or empty", "name");
            
            PreparedStatement prepared = await _findByName;
            BoundStatement bound = prepared.Bind(name);

            RowSet rows = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            return Role.FromRow(rows.SingleOrDefault());
        }
        
        protected void Dispose(bool disposing)
        {
            if (_disposeOfSession)
                _session.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
