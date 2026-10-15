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

export const DIMENSIONS: Array<'origin' | 'scope' | 'country'>;
export const MARKER_TEXT: Record<string, string>;
export interface LabelRow extends FlatCounts { key: string; label: string; rate: string }
export function labelText(row: { value: string | null; marker: string | null }, kind: string): string;
export function countryName(code: string): string;
export function dimensionRows(report: StatsReport, kind: string, circuit?: string): LabelRow[];
export function labelCircuitRows(report: StatsReport, kind: string, key: string): CircuitRow[];
export function labelTotals(report: StatsReport, kind: string, key: string, circuit?: string): FlatCounts & { rate: string };
export const MAP_SHADES: number;
export function answered(counts: { completed: number; error: number; cancelled: number }): number;
export function shadeFor(count: number, max: number): number;
export function mapShades(report: StatsReport, circuit?: string): Record<string, { count: number; shade: number }>;
export interface CountryDetail {
  code: string;
  name: string;
  total: { completed: number; error: number; cancelled: number; answered: number };
  circuits: Array<{ circuit: string; completed: number; error: number; cancelled: number; answered: number }>;
}
export function countryDetail(report: StatsReport, code: string): CountryDetail;
