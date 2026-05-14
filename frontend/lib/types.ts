export type UserView = {
  id: string;
  username: string;
  created_at: string;
};

export type AuthOutput = {
  token: string;
  user: UserView;
};

export type ExitNode = {
  id: string;
  user_id: string;
  name: string;
  proxy_yaml: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type OutputProfile = {
  id: string;
  name: string;
  sub_token: string;

  upstream_url: string;
  last_upstream_fetched_at: string | null;
  last_upstream_fetch_status: string | null;
  last_upstream_fetch_error: string | null;

  bridge_node_names: string[];
  exit_node_ids: string[];

  custom_rules: string | null;
  enabled: boolean;

  cached_upstream_count: number;
  cached_bridge_count: number;
  cached_chain_count: number;
  cached_missing_bridges: string[];
  cached_at: string | null;

  created_at: string;
  updated_at: string;
};

export type UpstreamNode = {
  name: string;
  type: string | null;
  server: string | null;
  port: number | null;
};

export type GenerateResult = {
  upstream_count: number;
  bridge_count: number;
  chain_count: number;
  missing_bridges: string[];
  sub_url: string;
};

export type HistoryItem = {
  id: string;
  content_hash: string;
  proxy_count: number;
  trigger_kind: string; // 'manual' | 'auto'
  fetched_at: string;
  has_previous: boolean;
};
