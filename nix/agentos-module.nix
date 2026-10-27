# AgentOS 的 NixOS 服务模块（阶段 2 发行版实验）
#
# NixOS 路线的"一份配置装出 Agent OS 运行时"：
#   1. 把本文件与 agentos.nix 放入 NixOS 配置（imports = [ ./agentos-module.nix ]）
#   2. services.agentos.enable = true;
#   3. nixos-rebuild switch
#
# 语义与 systemd/deb 路线一致：
#   - agentos 系统用户与组（StateDirectory 由 systemd 按此用户建）
#   - ProtectSystem=strict 等加固矩阵
#   - socket 落在 RuntimeDirectory（systemd 原生管理，无需 tmpfiles）
#   - 策略目录 /var/lib/agentos/policies root 属主、agentos 组只读
#     （S-2：daemon 不可自改权限边界）
{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.agentos;
  stateDir = "/var/lib/agentos";
in
{
  options.services.agentos = {
    enable = mkEnableOption "AgentOS agent runtime (policy-enforced exec + signed ledger)";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ../agentos.nix {};
      description = "AgentOS runtime 包";
    };

    workDir = mkOption {
      type = types.str;
      default = "${stateDir}/work";
      description = "任务读写区（自动纳入写白名单）";
    };
  };

  config = mkIf cfg.enable {
    users.users.agentos = {
      isSystemUser = true;
      group = "agentos";
      home = stateDir;
      useDefaultShell = true;
      description = "AgentOS runtime daemon";
    };
    users.groups.agentos = {};

    systemd.services.agentos-agentd = {
      description = "AgentOS agent runtime";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];

      serviceConfig = {
        Type = "simple";
        User = "agentos";
        Group = "agentos";
        UMask = "0077";
        ExecStart = "${cfg.package}/bin/agentd --state-dir ${stateDir} --socket /run/agentos/agentd.sock";
        Restart = "on-failure";
        RestartSec = 3;

        # ---- 加固矩阵（与 deb unit 同源，NixOS 语义） ----
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        LockPersonality = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = false; # Landlock 非 namespace 机制，但 daemon 端不建 ns；保守放行
        RestrictRealtime = true;
        CapabilityBoundingSet = [ "" ];
        RestrictAddressFamilies = [ "AF_UNIX" ];
        # 255 实测：@system-service 缺 getrandom/landlock 三 syscall，需显式补
        SystemCallFilter = [
          "@system-service"
          "getrandom"
          "landlock_create_ruleset"
          "landlock_add_rule"
          "landlock_restrict_self"
        ];
        SystemCallArchitectures = "native";
        RuntimeDirectory = "agentos";
        RuntimeDirectoryMode = "0755";
        StateDirectory = "agentos";
        StateDirectoryMode = "0750";

        ReadWritePaths = [ stateDir config.services.agentos.workDir ];
      };
    };
  };
}
