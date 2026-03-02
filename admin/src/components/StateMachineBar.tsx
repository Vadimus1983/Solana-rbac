import React from "react";
import type { OrgStateKind } from "../types";

interface Props {
  state: OrgStateKind;
}

const STEPS: { label: string; key: OrgStateKind }[] = [
  { label: "Idle", key: "idle" },
  { label: "Updating", key: "updating" },
  { label: "Recomputing", key: "recomputing" },
];

export default function StateMachineBar({ state }: Props) {
  const currentIdx = STEPS.findIndex((s) => s.key === state);

  return (
    <div className="flex items-center gap-2">
      {STEPS.map((step, i) => {
        const isActive = i === currentIdx;
        const isDone = i < currentIdx;
        return (
          <React.Fragment key={step.key}>
            <div className="flex flex-col items-center min-w-[4.5rem]">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold border-2 ${
                  isActive
                    ? "bg-indigo-600 border-indigo-600 text-white"
                    : isDone
                    ? "bg-green-500 border-green-500 text-white"
                    : "bg-white border-gray-300 text-gray-400"
                }`}
              >
                {isDone ? "✓" : i + 1}
              </div>
              <span
                className={`mt-1 text-xs font-medium text-center ${
                  isActive
                    ? "text-indigo-700"
                    : isDone
                    ? "text-green-700"
                    : "text-gray-400"
                }`}
              >
                {step.label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                className={`h-0.5 w-8 mb-4 ${
                  isDone ? "bg-green-400" : isActive ? "bg-indigo-300" : "bg-gray-200"
                }`}
              />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
