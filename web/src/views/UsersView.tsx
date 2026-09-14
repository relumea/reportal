// The Users view: who this install knows, what each may do, and the bearer
// token this browser sends.
//
// Token auth is off by default, and the view says so rather than rendering an
// empty user table as if it meant something: with auth off the API is the
// single local user's and every request already carries all three permissions.
// With it on, a token is required and this page is where an operator creates
// users and where any browser stores the token it sends; the token is shown
// once, when it is created or rotated, because only its digest is stored.

import { useState } from "react";
import type { ReactNode } from "react";

import { api, storedToken, storeToken } from "../api";
import {
  Badge,
  Button,
  CodeBlock,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  KeyValue,
  Loading,
  Muted,
  NA,
  Note,
  Panel,
  Toolbar,
} from "../components";
import { ROLES } from "../constants";
import type {
  ActivityItem,
  ActivityPayload,
  FeedbackPayload,
  Me,
  OrganisationRow,
  OrganisationsPayload,
  SecretRow,
  SecretsPayload,
  TeamRow,
  TeamsPayload,
  UserRow,
  UsersPayload,
} from "../types";
import { useAsync } from "../useAsync";

/** The token this browser sends, with the control that sets or clears it. */
function TokenField({ onSaved }: { onSaved: () => void }): ReactNode {
  const [draft, setDraft] = useState(storedToken());
  const [message, setMessage] = useState("");
  const save = (value: string): void => {
    storeToken(value.trim());
    setDraft(value.trim());
    setMessage(value.trim() ? "Saved. Requests now carry this token." : "Cleared.");
    onSaved();
  };
  return (
    <>
      <Toolbar>
        <Field label="Bearer token">
          <input
            placeholder="reportal_..."
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") save(draft);
            }}
          />
        </Field>
        <Button onClick={() => save(draft)}>Save</Button>
        <Button tone="ghost" onClick={() => save("")}>
          Clear
        </Button>
      </Toolbar>
      {message ? <Muted>{message}</Muted> : null}
    </>
  );
}

/** One new user's name and role, and the token the server hands back once. */
function NewUser({ onCreated }: { onCreated: () => void }): ReactNode {
  const [name, setName] = useState("");
  const [role, setRole] = useState("analyst");
  const [token, setToken] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  return (
    <>
      <Toolbar>
        <Field label="Name">
          <input value={name} onChange={(event) => setName(event.target.value)} />
        </Field>
        <Field label="Role">
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            {ROLES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
        <Button
          tone="primary"
          pending={busy}
          disabled={!name.trim()}
          onClick={() => {
            setError(null);
            setBusy(true);
            api<UserRow & { token: string }>("/users", {
              method: "POST",
              json: { name: name.trim(), role },
            })
              .then((created) => {
                setToken(created.token);
                setName("");
                onCreated();
              })
              .catch((failure: unknown) => setError(failure))
              .finally(() => setBusy(false));
          }}
        >
          Create user
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} /> : null}
      {token ? (
        <>
          <Muted>This token is shown once; only its digest is stored.</Muted>
          <CodeBlock text={token} title="bearer token" />
        </>
      ) : null}
    </>
  );
}

/** The teams, their membership and the create/delete controls. */
function TeamsPanel({ users, onChanged }: { users: UserRow[]; onChanged: () => void }): ReactNode {
  const teams = useAsync(() => api<TeamsPayload>("/teams"), []);
  const organisations = useAsync(() => api<OrganisationsPayload>("/organisations"), []);
  const [name, setName] = useState("");
  const [organisationName, setOrganisationName] = useState("");
  const [member, setMember] = useState<Record<number, string>>({});
  const [open, setOpen] = useState<TeamRow | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const act = (key: string, work: () => Promise<unknown>): void => {
    setError(null);
    setBusy(key);
    void work()
      .then(() => {
        teams.reload();
        onChanged();
      })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(""));
  };

  const rows = teams.data?.teams ?? [];
  return (
    <Panel
      title="Teams"
      subtitle="A team scopes the binaries and collections that carry its visibility."
      actions={
        <Button tone="ghost" onClick={teams.reload}>
          Reload
        </Button>
      }
    >
      {teams.error ? <ErrorNote error={teams.error} onRetry={teams.reload} /> : null}
      {error ? <ErrorNote error={error} /> : null}
      <Toolbar>
        <Field label="New team">
          <input
            placeholder="team name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Button
          tone="primary"
          pending={busy === "create"}
          disabled={!name.trim()}
          onClick={() =>
            act("create", () =>
              api("/teams", { method: "POST", json: { name: name.trim() } }).then(() => setName("")),
            )
          }
        >
          Create team
        </Button>
        <Field label="New organisation">
          <input
            placeholder="organisation name"
            value={organisationName}
            onChange={(event) => setOrganisationName(event.target.value)}
          />
        </Field>
        <Button
          pending={busy === "create-organisation"}
          disabled={!organisationName.trim()}
          onClick={() =>
            act("create-organisation", () =>
              api("/organisations", {
                method: "POST",
                json: { name: organisationName.trim() },
              }).then(() => {
                setOrganisationName("");
                organisations.reload();
              }),
            )
          }
        >
          Create organisation
        </Button>
      </Toolbar>
      <Muted>
        An organisation groups teams and decides nothing about access: the team that owns an object
        is still what permits a read or a write.
      </Muted>
      {(organisations.data?.organisations ?? []).length ? (
        <DataTable
          columns={[
            { label: "ID", key: "id", numeric: true },
            { label: "Organisation", key: "name" },
            {
              label: "Teams",
              render: (row: OrganisationRow) =>
                row.teams.length ? row.teams.map((team) => team.name).join(", ") : "n/a",
            },
            {
              label: "",
              render: (row: OrganisationRow) => (
                <ConfirmButton
                  label="Delete"
                  message={`Delete organisation ${row.name}? Its teams stay.`}
                  pending={busy === `organisation-${row.id}`}
                  onConfirm={() =>
                    act(`organisation-${row.id}`, () =>
                      api(`/organisations/${row.id}`, { method: "DELETE" }).then(() =>
                        organisations.reload(),
                      ),
                    )
                  }
                />
              ),
            },
          ]}
          rows={organisations.data?.organisations ?? []}
          rowKey={(row: OrganisationRow) => row.id}
        />
      ) : null}
      {teams.data === undefined ? (
        <Loading label="Loading teams" />
      ) : rows.length === 0 ? (
        <EmptyState>No teams. A workspace-wide install does not need one.</EmptyState>
      ) : (
        <DataTable
          columns={[
            { label: "ID", key: "id", numeric: true },
            { label: "Name", key: "name" },
            { label: "Members", key: "member_count", numeric: true },
            { label: "Organisation", render: (row: TeamRow) => row.organisation_name ?? "n/a" },
            { label: "Description", key: "description" },
            {
              label: "Add member",
              render: (row: TeamRow) => (
                <select
                  aria-label={`add a member to ${row.name}`}
                  value={member[row.id] ?? ""}
                  onChange={(event) => {
                    const userId = event.target.value;
                    setMember((current) => ({ ...current, [row.id]: userId }));
                    if (userId) {
                      act(`member-${row.id}`, () =>
                        api(`/teams/${row.id}/members`, {
                          method: "POST",
                          json: { user_id: Number(userId) },
                        }).then(() => setMember((current) => ({ ...current, [row.id]: "" }))),
                      );
                    }
                  }}
                >
                  <option value="">pick a user</option>
                  {users.map((user) => (
                    <option key={user.id} value={user.id}>
                      {user.name}
                    </option>
                  ))}
                </select>
              ),
            },
            {
              label: "Organisation",
              render: (row: TeamRow) => (
                <select
                  aria-label={`move ${row.name} to an organisation`}
                  value={row.organisation_id ?? ""}
                  onChange={(event) =>
                    act(`organisation-${row.id}`, () =>
                      api(`/teams/${row.id}/organisation`, {
                        method: "PUT",
                        json: {
                          organisation_id: event.target.value
                            ? Number(event.target.value)
                            : null,
                        },
                      }).then(() => organisations.reload()),
                    )
                  }
                >
                  <option value="">none</option>
                  {(organisations.data?.organisations ?? []).map((organisation) => (
                    <option key={organisation.id} value={organisation.id}>
                      {organisation.name}
                    </option>
                  ))}
                </select>
              ),
            },
            {
              label: "Actions",
              render: (row: TeamRow) => (
                <div className="actions-cell">
                  <Button size="sm" onClick={() => setOpen(open?.id === row.id ? null : row)}>
                    {open?.id === row.id ? "Hide members" : "Members"}
                  </Button>
                  <ConfirmButton
                    label="Delete"
                    message={`Delete team ${row.name}? The objects it owns return to the workspace.`}
                    pending={busy === `delete-${row.id}`}
                    onConfirm={() => act(`delete-${row.id}`, () => api(`/teams/${row.id}`, { method: "DELETE" }))}
                  />
                </div>
              ),
            },
          ]}
          rows={rows}
          rowKey={(row) => row.id}
        />
      )}
      {open ? (
        <TeamMembers
          team={open}
          busy={busy}
          onRole={(userId, role) =>
            act(`role-${open.id}-${userId}`, () =>
              api(`/teams/${open.id}/members/${userId}/role`, {
                method: "PUT",
                json: { role },
              }).then(() => setOpen((current) => current)),
            )
          }
          onRemove={(userId) =>
            act(`remove-${open.id}-${userId}`, () =>
              api(`/teams/${open.id}/members/${userId}`, { method: "DELETE" }),
            )
          }
        />
      ) : null}
    </Panel>
  );
}

/** One team's members with the role each holds in it. */
function TeamMembers({
  team,
  busy,
  onRole,
  onRemove,
}: {
  team: TeamRow;
  busy: string;
  onRole: (userId: number, role: string) => void;
  onRemove: (userId: number) => void;
}): ReactNode {
  const detail = useAsync(() => api<TeamRow>(`/teams/${team.id}`), [team.id]);
  const members = detail.data?.members ?? [];
  return (
    <>
      <h3>{team.name} members</h3>
      <Muted>
        A team owner may rename the team, set its members and change roles; a member works on what
        the team owns. An admin may manage any team, which is what keeps a lockout recoverable.
      </Muted>
      {detail.error ? <ErrorNote error={detail.error} onRetry={detail.reload} /> : null}
      <DataTable
        columns={[
          { label: "ID", key: "id", numeric: true },
          { label: "User", key: "name" },
          { label: "Portal role", key: "portal_role" },
          {
            label: "Team role",
            render: (row) => (
              <select
                aria-label={`role of ${row.name} in ${team.name}`}
                value={row.team_role}
                disabled={busy.startsWith("role-")}
                onChange={(event) => onRole(row.id, event.target.value)}
              >
                <option value="owner">owner</option>
                <option value="member">member</option>
              </select>
            ),
          },
          {
            label: "",
            render: (row) => (
              <Button
                size="sm"
                tone="ghost"
                pending={busy === `remove-${team.id}-${row.id}`}
                onClick={() => onRemove(row.id)}
              >
                Remove
              </Button>
            ),
          },
        ]}
        rows={members}
        rowKey={(row) => row.id}
        empty={<Muted>No members yet.</Muted>}
      />
    </>
  );
}

/** What was done here and by whom, plus the local feedback notes. */
function ActivityPanel(): ReactNode {
  const [actor, setActor] = useState("");
  const path = `/users/activity?limit=50${actor ? `&actor=${encodeURIComponent(actor)}` : ""}`;
  const feed = useAsync(() => api<ActivityPayload>(path), [path]);
  const notes = useAsync(() => api<FeedbackPayload>("/users/feedback?limit=20"), []);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const items: ActivityItem[] = feed.data?.items ?? [];
  return (
    <Panel
      title="Activity"
      subtitle="Derived from the action journal and the analysis log; the actor is who made each write."
      actions={
        <>
          <select
            aria-label="filter the activity by actor"
            value={actor}
            onChange={(event) => setActor(event.target.value)}
          >
            <option value="">every actor</option>
            {(feed.data?.actors ?? []).map((entry) => (
              <option key={entry.actor} value={entry.actor}>
                {entry.actor || "no request"} ({entry.actions})
              </option>
            ))}
          </select>
          <Button tone="ghost" onClick={feed.reload}>
            Reload
          </Button>
        </>
      }
    >
      {feed.error ? <ErrorNote error={feed.error} onRetry={feed.reload} /> : null}
      {feed.data === undefined ? (
        <Loading label="Loading the activity" />
      ) : items.length === 0 ? (
        <EmptyState>Nothing recorded yet. A write through the API, the CLI or MCP shows here.</EmptyState>
      ) : (
        <DataTable
          columns={[
            { label: "When", key: "at", mono: true },
            { label: "Actor", render: (row) => row.actor || "n/a" },
            { label: "Kind", render: (row) => <Badge mono>{row.kind}</Badge> },
            { label: "Description", key: "description" },
            { label: "Status", key: "status" },
          ]}
          rows={items}
          rowKey={(row) => row.id}
        />
      )}
      <Toolbar>
        <Field label="Feedback about reportal">
          <input
            placeholder="what would help"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
          />
        </Field>
        <Button
          pending={busy}
          disabled={!message.trim()}
          onClick={() => {
            setError(null);
            setBusy(true);
            void api("/users/feedback", { method: "POST", json: { message: message.trim() } })
              .then(() => {
                setMessage("");
                feed.reload();
                notes.reload();
              })
              .catch((failure: unknown) => setError(failure))
              .finally(() => setBusy(false));
          }}
        >
          Store note
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} /> : null}
      {notes.data && notes.data.feedback.length > 0 ? (
        <DataTable
          columns={[
            { label: "When", key: "created_at", mono: true },
            { label: "Actor", render: (row) => row.actor || "n/a" },
            { label: "Note", key: "body" },
          ]}
          rows={notes.data.feedback}
          rowKey={(row) => row.id}
        />
      ) : null}
    </Panel>
  );
}

/** The stored credentials: names, scope and a last-four hint, never a value. */
function SecretsPanel(): ReactNode {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [scope, setScope] = useState("local");
  const [teamId, setTeamId] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [note, setNote] = useState("");
  const query = useAsync(() => api<SecretsPayload>("/secrets"), []);
  const rows = query.data?.secrets ?? [];

  const act = (key: string, message: string, work: () => Promise<unknown>): void => {
    setError(null);
    setNote("");
    setBusy(key);
    void work()
      .then(() => {
        setNote(message);
        setValue("");
        setName("");
        query.reload();
      })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(""));
  };

  const store = (): void => {
    if (!name || !value) return;
    act("set", `Stored ${name}.`, () =>
      api(`/secrets/${encodeURIComponent(name)}`, {
        method: "PUT",
        json: { value, scope, team_id: teamId ? Number(teamId) : undefined },
      }),
    );
  };

  const remove = (row: SecretRow): void =>
    act(`rm:${row.name}`, `Removed ${row.name}.`, () =>
      api(
        `/secrets/${encodeURIComponent(row.name)}?scope=${row.scope}` +
          (row.team_id ? `&team_id=${row.team_id}` : ""),
        { method: "DELETE" },
      ),
    );

  return (
    <Panel
      title="Secrets"
      subtitle="Named credentials the workspace or a team holds. A read never returns the value."
      actions={
        <Button tone="ghost" onClick={query.reload}>
          Reload
        </Button>
      }
    >
      {error ? <ErrorNote error={error} /> : null}
      {note ? <Note>{note}</Note> : null}
      <Toolbar>
        <Field label="Name" hint="A lowercase dotted path, e.g. virustotal.api_key.">
          <input value={name} onChange={(event) => setName(event.target.value)} />
        </Field>
        <Field label="Value">
          <input
            type="password"
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
        </Field>
        <Field label="Scope">
          <select value={scope} onChange={(event) => setScope(event.target.value)}>
            <option value="local">local</option>
            <option value="team">team</option>
          </select>
        </Field>
        <Field label="Team">
          <input
            placeholder="team id"
            value={teamId}
            onChange={(event) => setTeamId(event.target.value)}
          />
        </Field>
        <Button tone="primary" pending={busy === "set"} disabled={!name || !value} onClick={store}>
          Store
        </Button>
      </Toolbar>
      {query.error ? <ErrorNote error={query.error} onRetry={query.reload} /> : null}
      {query.data === undefined ? (
        <Loading label="Loading the secret store" />
      ) : rows.length === 0 ? (
        <EmptyState>
          No credentials stored. A value set here is what an external source reads; only its
          name, scope, length and last four characters are ever shown again.
        </EmptyState>
      ) : (
        <DataTable
          columns={[
            { label: "Name", mono: true, key: "name" },
            { label: "Scope", key: "scope" },
            { label: "Team", numeric: true, render: (row) => (row.team_id ? String(row.team_id) : "") },
            { label: "Bytes", numeric: true, render: (row) => String(row.length) },
            { label: "Hint", mono: true, render: (row) => row.hint || "n/a" },
            { label: "Updated", mono: true, key: "updated_at" },
            {
              label: "",
              render: (row) => (
                <Button
                  size="sm"
                  pending={busy === `rm:${row.name}`}
                  onClick={() => remove(row)}
                >
                  Remove
                </Button>
              ),
            },
          ]}
          rows={rows}
          rowKey={(row) => `${row.name}:${row.scope}:${row.team_id ?? 0}`}
        />
      )}
    </Panel>
  );
}

export function UsersView(): ReactNode {
  const me = useAsync(() => api<Me>("/iam/me"), []);
  const users = useAsync(() => api<UsersPayload>("/users"), []);
  const [token, setToken] = useState("");
  const [rowError, setRowError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const reload = (): void => {
    me.reload();
    users.reload();
  };

  const act = (key: string, work: () => Promise<unknown>): void => {
    setRowError(null);
    setBusy(key);
    void work()
      .then(reload)
      .catch((failure: unknown) => setRowError(failure))
      .finally(() => setBusy(""));
  };

  const authRequired = me.data?.auth === "required";
  const rows = users.data?.users ?? [];

  const setActiveTeam = (value: string): void => {
    act("active-team", () =>
      api("/iam/active-team", {
        method: "PUT",
        json: { team_id: value === "" ? null : Number(value) },
      }),
    );
  };

  return (
    <>
      <Panel
        title="Identity"
        subtitle="Who this install knows, what each may do, and the token this browser sends."
        actions={
          <Button tone="ghost" onClick={reload}>
            Reload
          </Button>
        }
      >
        {me.error ? <ErrorNote error={me.error} onRetry={me.reload} /> : null}
        {me.data === undefined ? (
          <Loading label="Loading the identity" />
        ) : (
          <KeyValue
            rows={[
              ["mode", authRequired ? "token auth required" : "single local user"],
              ["you", me.data.user ? me.data.user.name : "no token in this browser"],
              ["role", me.data.role ?? NA],
              [
                "permissions",
                me.data.permissions.length
                  ? me.data.permissions.map((permission) => (
                      <Badge key={permission}>{permission}</Badge>
                    ))
                  : NA,
              ],
            ]}
          />
        )}
        {authRequired && me.data?.user ? (
          <Toolbar>
            <Field
              label="Active team"
              hint="The team this caller works in; the binaries view starts new uploads in its scope."
            >
              <select
                aria-label="Active team"
                value={
                  me.data.user.active_team_id === null
                    ? ""
                    : String(me.data.user.active_team_id)
                }
                disabled={busy === "active-team"}
                onChange={(event) => setActiveTeam(event.target.value)}
              >
                <option value="">No active team</option>
                {me.data.teams.map((team) => (
                  <option key={team.id} value={team.id}>
                    team {team.name}
                  </option>
                ))}
              </select>
            </Field>
          </Toolbar>
        ) : null}
        <Muted>
          A loopback install needs no token and every request carries all three permissions. A bind
          another machine can reach refuses to start without auth: set <code>REPORTAL_AUTH</code> or{" "}
          <code>[auth] required = true</code> and create a user.
        </Muted>
        <TokenField
          onSaved={() => {
            reload();
          }}
        />
      </Panel>
      <Panel
        title="Users"
        subtitle={
          users.data === undefined
            ? "Creates a user and prints its token once."
            : `${users.data.count} user(s).`
        }
      >
        {users.error ? <ErrorNote error={users.error} onRetry={users.reload} /> : null}
        {rowError ? <ErrorNote error={rowError} /> : null}
        <NewUser onCreated={reload} />
        {users.data === undefined ? (
          <Loading label="Loading users" />
        ) : rows.length === 0 ? (
          <EmptyState>No users. A loopback-only install does not need one.</EmptyState>
        ) : (
          <DataTable
            columns={[
              { label: "ID", key: "id", numeric: true },
              { label: "Name", key: "name" },
              {
                label: "Role",
                render: (row) => (
                  <select
                    aria-label={`role of ${row.name}`}
                    value={row.role}
                    disabled={busy === `role-${row.id}`}
                    onChange={(event) =>
                      act(`role-${row.id}`, () =>
                        api(`/users/${row.id}`, { method: "PATCH", json: { role: event.target.value } }),
                      )
                    }
                  >
                    {ROLES.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                ),
              },
              {
                label: "State",
                render: (row) =>
                  row.disabled ? <Badge tone="warn">disabled</Badge> : <Badge tone="ok">active</Badge>,
              },
              { label: "Created", key: "created_at", mono: true },
              {
                label: "Actions",
                render: (row) => (
                  <div className="actions-cell">
                    <Button
                      size="sm"
                      pending={busy === `token-${row.id}`}
                      onClick={() =>
                        act(`token-${row.id}`, () =>
                          api<{ token: string }>(`/users/${row.id}/token`, { method: "POST" }).then(
                            (rotated) => setToken(rotated.token),
                          ),
                        )
                      }
                    >
                      New token
                    </Button>
                    <Button
                      size="sm"
                      onClick={() =>
                        act(`state-${row.id}`, () =>
                          api(`/users/${row.id}`, {
                            method: "PATCH",
                            json: { disabled: !row.disabled },
                          }),
                        )
                      }
                    >
                      {row.disabled ? "Enable" : "Disable"}
                    </Button>
                    <ConfirmButton
                      label="Delete"
                      message={`Delete user ${row.name}?`}
                      pending={busy === `delete-${row.id}`}
                      onConfirm={() =>
                        act(`delete-${row.id}`, () => api(`/users/${row.id}`, { method: "DELETE" }))
                      }
                    />
                  </div>
                ),
              },
            ]}
            rows={rows}
            rowKey={(row) => row.id}
          />
        )}
        {token ? (
          <>
            <Muted>A rotated token is shown once; the previous one stops working.</Muted>
            <CodeBlock text={token} title="bearer token" />
          </>
        ) : null}
      </Panel>
      <TeamsPanel users={rows} onChanged={reload} />
      <SecretsPanel />
      <ActivityPanel />
    </>
  );
}
