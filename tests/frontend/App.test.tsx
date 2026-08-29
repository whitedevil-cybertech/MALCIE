import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import App from "../../src/frontend/src/App";

describe("App", () => {
  it("renders the MALCIE heading", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "MALCIE" })).toBeInTheDocument();
  });
});
