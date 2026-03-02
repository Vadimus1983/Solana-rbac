import React from "react";
import type { OrgStateKind } from "../types";

const config: Record<OrgStateKind, { label: string; classes: string }> = {
  idle: {
    label: "Idle",
    classes: "bg-green-100 text-green-800",
  },
  updating: {
    label: "Updating",
    classes: "bg-yellow-100 text-yellow-800",
  },
  recomputing: {
    label: "Recomputing",
    classes: "bg-blue-100 text-blue-800",
  },
};

interface Props {
  state: OrgStateKind;
}

export default function OrgStateBadge({ state }: Props) {
  const { label, classes } = config[state] ?? config.idle;
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${classes}`}
    >
      {label}
    </span>
  );
}
