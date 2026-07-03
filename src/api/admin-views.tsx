/** @jsxImportSource hono/jsx */
/**
 * Admin panel pages, rendered with Hono JSX to match vaultwarden's Bootstrap
 * admin theme (see src/static/templates/admin/*.hbs in the vaultwarden repo).
 * Each exported `render*` helper returns a full HTML document string.
 */
import type { Config } from "../config"
import {
	SETTINGS_GROUPS,
	READONLY_FIELDS,
	type SettingField,
	type ReadonlyField
} from "../config-schema"
import { ADMIN_CSS, ADMIN_JS } from "./admin-assets"

const BOOTSTRAP_CSS = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
const BOOTSTRAP_JS = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"

type Page = "settings" | "users" | "organizations" | "diagnostics" | "login"

const BrandIcon = () => (
	<svg
		class="vaultur-icon"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="2"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"
	>
		<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
		<path d="M9 12l2 2 4-4" />
	</svg>
)

const ThemeSwitcher = () => (
	<li class="nav-item dropdown">
		<button
			class="btn btn-link nav-link py-0 px-0 px-md-2 dropdown-toggle d-flex align-items-center"
			id="bd-theme"
			type="button"
			aria-expanded="false"
			data-bs-toggle="dropdown"
			data-bs-display="static"
			aria-label="Toggle theme"
		>
			<span class="my-1 fs-4 theme-icon-active">
				<svg class="vw-theme-icon" width="20" height="20" aria-hidden="true">
					<use data-theme-icon-use href="#vw-icon-auto" />
				</svg>
			</span>
			<span class="d-md-none ms-2" id="bd-theme-text">
				Toggle theme
			</span>
		</button>
		<ul class="dropdown-menu dropdown-menu-end" aria-labelledby="bd-theme-text">
			{(
				[
					["light", "Light", "#vw-icon-sun"],
					["dark", "Dark", "#vw-icon-moon"],
					["auto", "Auto", "#vw-icon-auto"]
				] as const
			).map(([value, label, icon]) => (
				<li>
					<button
						type="button"
						class="dropdown-item d-flex align-items-center"
						data-bs-theme-value={value}
						aria-pressed={value === "auto" ? "true" : "false"}
					>
						<span class="me-2 fs-4 theme-icon">
							<svg class="vw-theme-icon" width="20" height="20" aria-hidden="true">
								<use data-theme-icon-use href={icon} />
							</svg>
						</span>
						{label}
					</button>
				</li>
			))}
		</ul>
	</li>
)

const NavBar = ({ page, loggedIn }: { page: Page; loggedIn: boolean }) => {
	const link = (href: string, label: string, active: boolean) => (
		<li class="nav-item">
			<a
				class={`nav-link${active ? " active" : ""}`}
				href={href}
				aria-current={active ? "page" : undefined}
			>
				{label}
			</a>
		</li>
	)
	return (
		<nav class="navbar navbar-expand-md bg-dark mb-4 shadow fixed-top" data-bs-theme="dark">
			<div class="container-xxl">
				<a class="navbar-brand d-flex align-items-center" href="/admin">
					<BrandIcon />
					Vaultur Admin
				</a>
				<button
					class="navbar-toggler"
					type="button"
					data-bs-toggle="collapse"
					data-bs-target="#navbarCollapse"
					aria-controls="navbarCollapse"
					aria-expanded="false"
					aria-label="Toggle navigation"
				>
					<span class="navbar-toggler-icon" />
				</button>
				<div class="collapse navbar-collapse" id="navbarCollapse">
					<ul class="navbar-nav me-auto">
						{loggedIn && link("/admin", "Settings", page === "settings")}
						{loggedIn && link("/admin/users/overview", "Users", page === "users")}
						{loggedIn &&
							link("/admin/organizations/overview", "Organizations", page === "organizations")}
						{loggedIn && link("/admin/diagnostics", "Diagnostics", page === "diagnostics")}
						<li class="nav-item">
							<a class="nav-link" href="/" target="_blank" rel="noreferrer">
								Vault
							</a>
						</li>
					</ul>
					<ul class="navbar-nav mx-3">
						<ThemeSwitcher />
					</ul>
					{loggedIn && (
						<a class="btn btn-sm btn-secondary" href="/admin/logout">
							Log Out
						</a>
					)}
				</div>
			</div>
		</nav>
	)
}

const ThemeSymbols = () => (
	<svg xmlns="http://www.w3.org/2000/svg" class="d-none">
		<symbol id="vw-icon-sun" viewBox="0 0 24 24">
			<circle cx="12" cy="12" r="5" fill="currentColor" />
			<g stroke="currentColor" stroke-linecap="round" stroke-width="1.5">
				<path d="M12 2v3M12 19v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M2 12h3M19 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12" />
			</g>
		</symbol>
		<symbol id="vw-icon-moon" viewBox="0 0 24 24">
			<path
				fill="currentColor"
				d="M18.4 17.8A9 8.6 0 0 1 13 2a10.5 10 0 1 0 9 14.4 9.4 9 0 0 1-3.6 1.4"
			/>
		</symbol>
		<symbol id="vw-icon-auto" viewBox="0 0 24 24">
			<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.5" />
			<path fill="currentColor" d="M12 3a9 9 0 1 1 0 18Z" />
		</symbol>
	</svg>
)

const Layout = ({
	page,
	loggedIn,
	children
}: {
	page: Page
	loggedIn: boolean
	children: unknown
}) => (
	<html lang="en" data-bs-theme="auto">
		<head>
			<meta charset="UTF-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1" />
			<meta name="robots" content="noindex,nofollow" />
			<link rel="icon" href="/favicon.ico" />
			<title>Vaultur Admin Panel</title>
			<link rel="stylesheet" href={BOOTSTRAP_CSS} />
			<style dangerouslySetInnerHTML={{ __html: ADMIN_CSS }} />
			<script dangerouslySetInnerHTML={{ __html: ADMIN_JS }} />
		</head>
		<body>
			<ThemeSymbols />
			<NavBar page={page} loggedIn={loggedIn} />
			{children as never}
			<script src={BOOTSTRAP_JS} />
		</body>
	</html>
)

function doc(node: unknown): string {
	return "<!DOCTYPE html>" + String(node)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export function renderLogin(error?: string): string {
	return doc(
		<Layout page="login" loggedIn={false}>
			<main class="container-xxl">
				{error && (
					<div class="alert alert-danger" role="alert">
						{error}
					</div>
				)}
				<div class="align-items-center p-3 mb-3 bg-secondary rounded shadow">
					<h6 class="text-white">Authentication key needed to continue</h6>
					<small class="text-white-50">Please provide the admin token below:</small>
					<form class="mt-2" method="post" action="/admin">
						<div class="input-group">
							<input
								type="password"
								class="form-control"
								name="token"
								placeholder="Enter admin token"
								autofocus
								autocomplete="current-password"
							/>
							<button type="submit" class="btn btn-primary">
								Enter
							</button>
						</div>
					</form>
				</div>
			</main>
		</Layout>
	)
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

const FieldRow = ({
	field,
	cfg,
	overridden
}: {
	field: SettingField
	cfg: Config
	overridden: boolean
}) => {
	const rowClass = `row my-2 align-items-center is-overridden-${overridden} alert-row`
	const title = `[${field.name}] ${field.description}`
	const id = `input_${field.name}`
	if (field.type === "checkbox") {
		return (
			<div class={rowClass} title={title}>
				<div class="col-sm-4 col-form-label">{field.label}</div>
				<div class="col-sm-8">
					<div class="form-check">
						<input
							class="form-check-input conf-checkbox"
							type="checkbox"
							id={id}
							name={field.name}
							checked={Boolean(field.get(cfg))}
						/>
						<label class="form-check-label" for={id}>
							{field.description}
						</label>
					</div>
				</div>
			</div>
		)
	}
	const raw = field.get(cfg)
	const value = raw == null ? "" : String(raw)
	return (
		<div class={rowClass} title={title}>
			<label for={id} class="col-sm-4 col-form-label">
				{field.label}
			</label>
			<div class="col-sm-8">
				<div class="input-group">
					<input
						class={`form-control conf-${field.type}`}
						id={id}
						type={field.type}
						name={field.name}
						value={value}
						placeholder={field.default ? `Default: ${field.default}` : undefined}
						spellcheck={false}
					/>
					{field.type === "password" && (
						<button class="btn btn-outline-secondary" type="button" data-vw-pw-toggle={id}>
							Show/hide
						</button>
					)}
				</div>
			</div>
		</div>
	)
}

const EmailExtras = ({ bindingPresent }: { bindingPresent: boolean }) => (
	<>
		<div class="row my-2 align-items-center">
			<label for="email_provider" class="col-sm-4 col-form-label">
				Email provider
			</label>
			<div class="col-sm-8">
				<input
					readonly
					class="form-control"
					id="email_provider"
					type="text"
					value="Cloudflare Email Sending"
					spellcheck={false}
				/>
			</div>
		</div>
		<div class="alert alert-info small mt-2" role="alert">
			Vaultur sends mail through the <span class="cf-badge">Cloudflare Email Sending</span> binding
			(<code>VAULTUR_EMAIL</code>)
			{bindingPresent ? " — configured." : " — not configured; add the binding in wrangler.jsonc."}{" "}
			Traditional SMTP host, port and credentials are not required.
		</div>
		<div
			class="row my-2 align-items-center pt-3 border-top"
			title="Send a test email to the given address"
		>
			<label for="smtp-test-email" class="col-sm-4 col-form-label">
				Test email
			</label>
			<div class="col-sm-8 input-group">
				<input
					class="form-control"
					id="smtp-test-email"
					type="email"
					placeholder="Enter test email"
					spellcheck={false}
				/>
				<button type="button" class="btn btn-outline-primary" id="smtpTest">
					Send test email
				</button>
			</div>
		</div>
	</>
)

export function renderSettings(props: {
	cfg: Config
	overridden: Set<string>
	bindingPresent: boolean
	adminTokenInsecure: boolean
}): string {
	const { cfg, overridden, bindingPresent } = props
	return doc(
		<Layout page="settings" loggedIn={true}>
			<main class="container-xxl">
				<div id="config-block" class="align-items-center p-3 mb-3 bg-secondary rounded shadow">
					<h6 class="text-white mb-3">Configuration</h6>
					<div class="small text-white mb-3">
						<span class="fw-bold">NOTE:</span> Settings saved here are stored in the database and
						override the environment variables. Overridden settings are shown with{" "}
						<span class="is-overridden-true alert-row px-1">a yellow background</span>. Secrets
						(admin token, push keys) can only be set via Cloudflare env/secrets and are read-only.
					</div>
					<form class="form" id="config-form" novalidate>
						{SETTINGS_GROUPS.map((g, i) => (
							<div class="card mb-3">
								<button
									id={`b_${g.group}`}
									type="button"
									class="card-header text-start btn btn-link text-decoration-none"
									aria-expanded={i === 0 ? "true" : "false"}
									aria-controls={`g_${g.group}`}
									data-bs-toggle="collapse"
									data-bs-target={`#g_${g.group}`}
								>
									{g.label}
								</button>
								<div id={`g_${g.group}`} class={`card-body collapse${i === 0 ? " show" : ""}`}>
									{g.fields.map((f) => (
										<FieldRow field={f} cfg={cfg} overridden={overridden.has(f.name)} />
									))}
									{g.group === "smtp" && <EmailExtras bindingPresent={bindingPresent} />}
								</div>
							</div>
						))}

						<div class="card mb-3">
							<button
								id="b_readonly"
								type="button"
								class="card-header text-start btn btn-link text-decoration-none"
								aria-expanded="false"
								aria-controls="g_readonly"
								data-bs-toggle="collapse"
								data-bs-target="#g_readonly"
							>
								Read-Only Config
							</button>
							<div id="g_readonly" class="card-body collapse">
								<div class="small mb-3">
									These options are set via Cloudflare environment variables/secrets and cannot be
									changed here. Update them with <code>wrangler secret put</code> or in{" "}
									<code>wrangler.jsonc</code>.
								</div>
								{READONLY_FIELDS.map((f: ReadonlyField) => {
									const id = `input_${f.name}`
									const value = f.value(cfg)
									return (
										<div
											class="row my-2 align-items-center alert-row"
											title={`[${f.name}] ${f.description}`}
										>
											<label for={id} class="col-sm-4 col-form-label">
												{f.label}
											</label>
											<div class="col-sm-8">
												<div class="input-group">
													<input
														readonly
														class="form-control"
														id={id}
														type={f.type}
														value={value}
														spellcheck={false}
													/>
													{f.type === "password" && (
														<button
															class="btn btn-outline-secondary"
															type="button"
															data-vw-pw-toggle={id}
														>
															Show/hide
														</button>
													)}
												</div>
											</div>
										</div>
									)
								})}
							</div>
						</div>

						<button type="submit" class="btn btn-primary">
							Save
						</button>
						<button type="button" class="btn btn-danger float-end" id="deleteConf">
							Reset defaults
						</button>
					</form>
				</div>
			</main>
		</Layout>
	)
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export interface AdminUserRow {
	id: string
	name: string
	email: string
	emailVerified: boolean
	twoFactorEnabled: boolean
	userEnabled: boolean
	createdAt: string | null
	lastActive: string | null
	cipherCount: number
	attachmentCount: number
	attachmentSize: number
	organizationCount: number
}

function fmtDate(iso: string | null): string {
	if (!iso) return "—"
	return iso.slice(0, 16).replace("T", " ")
}
function fmtBytes(n: number): string {
	if (!n) return "0 B"
	const u = ["B", "KB", "MB", "GB", "TB"]
	let i = 0
	let v = n
	while (v >= 1024 && i < u.length - 1) {
		v /= 1024
		i++
	}
	return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`
}

const ActionBtn = ({
	act,
	uuid,
	email,
	label,
	danger
}: {
	act: string
	uuid: string
	email: string
	label: string
	danger?: boolean
}) => (
	<button
		type="button"
		class={`btn btn-sm btn-link p-0 border-0${danger ? " text-danger" : ""}`}
		data-act={act}
		data-uuid={uuid}
		data-email={email}
	>
		{label}
	</button>
)

export function renderUsers(users: AdminUserRow[]): string {
	return doc(
		<Layout page="users" loggedIn={true}>
			<main class="container-xxl">
				<div id="users-block" class="my-3 p-3 rounded shadow">
					<h6 class="border-bottom pb-2 mb-3">Registered Users ({users.length})</h6>
					<div class="table-responsive-xl small">
						<table id="users-table" class="table table-sm table-striped table-hover align-middle">
							<thead>
								<tr>
									<th class="vw-account-details">User</th>
									<th class="vw-created-at">Created</th>
									<th class="vw-last-active">Last active</th>
									<th>Entries</th>
									<th>Attachments</th>
									<th>Orgs</th>
									<th class="vw-actions text-end">Actions</th>
								</tr>
							</thead>
							<tbody>
								{users.length === 0 && (
									<tr>
										<td colspan={7} class="text-center text-muted py-3">
											No users yet.
										</td>
									</tr>
								)}
								{users.map((u) => (
									<tr>
										<td>
											<strong>{u.name || "—"}</strong>
											<span class="d-block">{u.email}</span>
											<span class="d-block mt-1">
												{!u.userEnabled && <span class="badge bg-danger me-1">Disabled</span>}
												{u.twoFactorEnabled && <span class="badge bg-success me-1">2FA</span>}
												{u.emailVerified ? (
													<span class="badge bg-success me-1">Verified</span>
												) : (
													<span class="badge bg-warning text-dark me-1">Unverified</span>
												)}
											</span>
										</td>
										<td>{fmtDate(u.createdAt)}</td>
										<td>{fmtDate(u.lastActive)}</td>
										<td>{u.cipherCount}</td>
										<td>
											{u.attachmentCount > 0
												? `${u.attachmentCount} · ${fmtBytes(u.attachmentSize)}`
												: "0"}
										</td>
										<td>{u.organizationCount}</td>
										<td class="text-end px-1">
											{u.twoFactorEnabled && (
												<>
													<ActionBtn
														act="remove-2fa"
														uuid={u.id}
														email={u.email}
														label="Remove 2FA"
													/>
													<br />
												</>
											)}
											<ActionBtn
												act="deauth"
												uuid={u.id}
												email={u.email}
												label="Deauthorize sessions"
											/>
											<br />
											{u.userEnabled ? (
												<ActionBtn act="disable" uuid={u.id} email={u.email} label="Disable User" />
											) : (
												<ActionBtn act="enable" uuid={u.id} email={u.email} label="Enable User" />
											)}
											<br />
											<ActionBtn
												act="delete"
												uuid={u.id}
												email={u.email}
												label="Delete User"
												danger
											/>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</div>

				<div id="invite-block" class="align-items-center p-3 mb-3 bg-secondary rounded shadow">
					<h6 class="text-white">Invite User</h6>
					<form class="mt-2" id="invite-form">
						<div class="input-group w-50">
							<input
								type="email"
								class="form-control"
								id="invite-email"
								placeholder="email@example.com"
								required
								spellcheck={false}
							/>
							<button type="submit" class="btn btn-primary" data-act="invite">
								Invite
							</button>
						</div>
					</form>
				</div>
			</main>
		</Layout>
	)
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

export interface AdminOrgRow {
	id: string
	name: string
	billingEmail: string | null
	userCount: number
	cipherCount: number
}

export function renderOrganizations(orgs: AdminOrgRow[]): string {
	return doc(
		<Layout page="organizations" loggedIn={true}>
			<main class="container-xxl">
				<div id="organizations-block" class="my-3 p-3 rounded shadow">
					<h6 class="border-bottom pb-2 mb-3">Organizations ({orgs.length})</h6>
					<div class="table-responsive-xl small">
						<table id="orgs-table" class="table table-sm table-striped table-hover align-middle">
							<thead>
								<tr>
									<th>Organization</th>
									<th>Billing email</th>
									<th>Users</th>
									<th>Entries</th>
									<th class="vw-actions text-end">Actions</th>
								</tr>
							</thead>
							<tbody>
								{orgs.length === 0 && (
									<tr>
										<td colspan={5} class="text-center text-muted py-3">
											No organizations.
										</td>
									</tr>
								)}
								{orgs.map((o) => (
									<tr>
										<td>
											<strong>{o.name}</strong>
											<span class="d-block">
												<span class="badge bg-success font-monospace">{o.id}</span>
											</span>
										</td>
										<td>{o.billingEmail || "—"}</td>
										<td>{o.userCount}</td>
										<td>{o.cipherCount}</td>
										<td class="text-end px-1">
											<button
												type="button"
												class="btn btn-sm btn-link p-0 border-0 text-danger"
												data-act="delete-org"
												data-uuid={o.id}
												data-name={o.name}
											>
												Delete Organization
											</button>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</div>
			</main>
		</Layout>
	)
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

export interface DiagnosticsData {
	version: string
	dbType: string
	running: boolean
	userCount: number
	time: string
	domain: string
	emailEnabled: boolean
	pushEnabled: boolean
}

export function renderDiagnostics(d: DiagnosticsData): string {
	const rows: [string, unknown][] = [
		["Server version", d.version],
		["Database", d.dbType.toUpperCase()],
		[
			"Status",
			d.running ? (
				<span class="badge bg-success">Running</span>
			) : (
				<span class="badge bg-danger">Down</span>
			)
		],
		["Registered users", d.userCount],
		["Domain", d.domain],
		[
			"Email (Cloudflare)",
			d.emailEnabled ? (
				<span class="badge bg-success">Enabled</span>
			) : (
				<span class="badge bg-secondary">Disabled</span>
			)
		],
		[
			"Push notifications",
			d.pushEnabled ? (
				<span class="badge bg-success">Enabled</span>
			) : (
				<span class="badge bg-secondary">Disabled</span>
			)
		],
		["Server time (UTC)", d.time]
	]
	return doc(
		<Layout page="diagnostics" loggedIn={true}>
			<main class="container-xxl">
				<div class="my-3 p-3 rounded shadow">
					<h6 class="border-bottom pb-2 mb-3">Diagnostics</h6>
					<table class="table table-sm">
						<tbody>
							{rows.map(([k, v]) => (
								<tr>
									<th style="width: 260px">{k}</th>
									<td>{v as never}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</main>
		</Layout>
	)
}
