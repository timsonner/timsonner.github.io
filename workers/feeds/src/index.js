import { createHandler } from "./handler.js";

const handler = createHandler();

export default {
  fetch(request) {
    return handler(request);
  }
};
