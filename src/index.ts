import { createApp } from "./app"
import type { Bindings } from "./env"
import { runScheduledJobs } from "./jobs/scheduled"

export { NotificationsHub } from "./durable/notifications-hub"

const app = createApp()

export default {
	fetch: app.fetch,
	async scheduled(controller: ScheduledController, env: Bindings, ctx: ExecutionContext) {
		ctx.waitUntil(runScheduledJobs(controller, env))
	}
} satisfies ExportedHandler<Bindings>
