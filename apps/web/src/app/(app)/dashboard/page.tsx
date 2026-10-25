// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { DashboardBoardView } from "@/components/dashboard/dashboard-board";
import { apiStatePage } from "@/components/api-state";
import { NotInitialized } from "@/components/not-initialized";
import { ApiError, api, segment } from "@/lib/api";
import type {
  DashboardBoard,
  DashboardOverview,
  DashboardPresetCatalog,
  DashboardSchedule,
  Operator,
} from "@/lib/types";

export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ id?: string }>;
}) {
  const params = await searchParams;
  let overview: DashboardOverview;
  let boards: DashboardBoard[];
  let presets: DashboardPresetCatalog;
  let me: Operator;
  try {
    const [overviewRes, listRes, presetsRes, meRes] = await Promise.all([
      api.get<DashboardOverview>("/dashboard"),
      api.get<{ dashboards: DashboardBoard[] }>("/dashboards"),
      api.get<DashboardPresetCatalog>("/dashboards/presets"),
      api.get<Operator>("/auth/me"),
    ]);
    overview = overviewRes;
    boards = listRes.dashboards;
    presets = presetsRes;
    me = meRes;
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  // An explicit ?id= wins so board switching still works once a home is pinned.
  const preferred =
    params.id ||
    (me.ui_preferences as { dashboard_home_id?: string } | undefined)?.dashboard_home_id;
  const activeMeta =
    boards.find((b) => b.id === preferred) ||
    boards.find((b) => b.is_default) ||
    boards[0];
  if (!activeMeta) {
    return <NotInitialized />;
  }

  let active: DashboardBoard;
  let schedules: DashboardSchedule[] = [];
  try {
    const [board, sched] = await Promise.all([
      api.get<DashboardBoard>(`/dashboards/${segment(activeMeta.id)}`),
      me.role === "admin"
        ? api
            .get<{ schedules: DashboardSchedule[] }>(`/dashboards/${segment(activeMeta.id)}/schedules`)
            .then((res) => res.schedules)
            .catch((error: unknown) => {
              if (error instanceof ApiError) return [] as DashboardSchedule[];
              throw error;
            })
        : Promise.resolve([] as DashboardSchedule[]),
    ]);
    active = board;
    schedules = sched;
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  return (
    <DashboardBoardView
      overview={overview}
      boards={boards}
      active={active}
      presets={presets}
      schedules={schedules}
      isAdmin={me.role === "admin"}
      canWrite={me.role !== "read_only"}
      operatorId={me.id}
    />
  );
}
