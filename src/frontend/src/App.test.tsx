import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import App from "./App";

describe("App", () => {
  it("renders the investigation workspace and incident controls", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Investigation workspace" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create incident/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/open existing incident by id/i)).toBeInTheDocument();
  });
});
