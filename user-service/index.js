import { ApolloServer } from "apollo-server";
import fs from "fs";
import jwt from "jsonwebtoken";
import { resolvers } from "./resolvers.js";

const typeDefs = fs.readFileSync("./schema.graphql", "utf8");

const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => {
    const token = req.headers.authorization || "";
    if (!token) return {};
    try {
      return {
        user: jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET)
      };
    } catch {
      return {};
    }
  }
});

server.listen({ port: 4001 }).then(() => {
  console.log("User Service running on port 4001");
});
