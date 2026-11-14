import { createHandler } from "./handler.js";

export default {
  fetch(request, env) {
    return createHandler({ env })(request);
  }
};
