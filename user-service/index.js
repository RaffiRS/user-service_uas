const { ApolloServer, gql } = require("apollo-server");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const db = require("./db");

const typeDefs = gql(fs.readFileSync("schema.graphql", "utf8"));

const resolvers = {
  Query: {
    me: async (_, __, ctx) => {
      if (!ctx.user) return null;
      const res = await db.query(
        "SELECT id, name, email FROM users WHERE id=$1",
        [ctx.user.id]
      );
      return res.rows[0];
    }
  },
  Mutation: {
    register: async (_, args) => {
      const hashed = await bcrypt.hash(args.password, 10);
      const res = await db.query(
        "INSERT INTO users(name,email,password) VALUES($1,$2,$3) RETURNING id,name,email",
        [args.name, args.email, hashed]
      );
      return res.rows[0];
    },
    login: async (_, args) => {
      const res = await db.query(
        "SELECT * FROM users WHERE email=$1",
        [args.email]
      );
      const user = res.rows[0];
      if (!user) throw new Error("User not found");

      const valid = await bcrypt.compare(args.password, user.password);
      if (!valid) throw new Error("Wrong password");

      const token = jwt.sign(
        { id: user.id },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      return { token };
    }
  }
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => {
    const auth = req.headers.authorization || "";
    if (!auth) return {};
    try {
      const decoded = jwt.verify(auth.replace("Bearer ", ""), process.env.JWT_SECRET);
      return { user: decoded };
    } catch {
      return {};
    }
  }
});

server.listen({ port: process.env.PORT || 4000 }).then(({ url }) => {
  console.log("User Service running at", url);
});
