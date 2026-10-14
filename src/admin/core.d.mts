// Types for core.mjs, so the TypeScript tests can import it. The browser never
// loads this file; it is not served (see ADMIN_ASSETS in src/admin.ts).
import type { StatsReport } from '../stats';

export const MAX_RANGE_DAYS: number;
export const PRESET_DAYS: number[];
export const DEFAULT_PRESET_DAYS: number;
export const MAX_BAR_WIDTH: number;
export const ERROR_LABELS: Record<string, string>;

export interface FlatCounts { requested: number; completed: number; error: number; cancelled: number; expired: number }
export interface CircuitRow extends FlatCounts { circuit: string; rate: string }
export interface DayRow extends FlatCounts { date: string }
export interface ErrorRow { circuit: string; code: string; label: string; count: number }
export interface Bar { series: string; date: string; value: number; x: number; y: number; width: number; height: number }

export function utcDay(ms: number): string;
export function rangeForPreset(days: number, nowMs: number): { from: string; to: string };
export function checkRange(from: unknown, to: unknown): { ok: true; days: number } | { ok: false; error: string };
export function successRate(completed: number, requested: number): string;
export function errorLabel(code: string): string;
export function isEmpty(report: StatsReport): boolean;
export function circuitRows(report: StatsReport): CircuitRow[];
export function totalsRow(report: StatsReport): FlatCounts & { rate: string };
export function errorRows(report: StatsReport, circuit?: string): ErrorRow[];
export function dailyRows(report: StatsReport, circuit?: string): DayRow[];
export function niceMax(max: number): number;
export function chartGeometry(
  rows: Array<Record<string, number | string>>,
  series: string[],
  box?: { width?: number; height?: number; left?: number; right?: number; top?: number; bottom?: number },
): { bars: Bar[]; ticks: Array<{ value: number; y: number }>; yMax: number; plot: { left: number; top: number; width: number; height: number; bottom: number } };
export function tokenFormatError(token: unknown): string;
export function retryAfterMinutes(header: string | null): number | null;
