// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
declare module "react-grid-layout" {
  import * as React from "react";

  export interface Layout {
    i: string;
    x: number;
    y: number;
    w: number;
    h: number;
    minW?: number;
    minH?: number;
    maxW?: number;
    maxH?: number;
    static?: boolean;
  }

  export interface ReactGridLayoutProps {
    className?: string;
    layout?: Layout[];
    cols?: number;
    rowHeight?: number;
    width?: number;
    margin?: [number, number];
    containerPadding?: [number, number] | null;
    isDraggable?: boolean;
    isResizable?: boolean;
    draggableHandle?: string;
    compactType?: "vertical" | "horizontal" | null;
    onLayoutChange?: (layout: Layout[]) => void;
    children?: React.ReactNode;
  }

  export default class ReactGridLayout extends React.Component<ReactGridLayoutProps> {}

  export function WidthProvider<P>(
    component: React.ComponentType<P>,
  ): React.ComponentType<Omit<P, "width">>;
}
