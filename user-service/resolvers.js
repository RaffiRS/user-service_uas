import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool } from "./db.js";

export const resolvers = {
  Query: {
    users: async () => {
      const res = await pool.query("SELECT id,name,email,role FROM users");
      return res.rows;
    },
    me: async (_, __, ctx) => ctx.user
  },

  Mutation: {
    register: async (_, args) => {
      const hash = await bcrypt.hash(args.password, 10);
      const res = await pool.query(
        "INSERT INTO users(name,email,password,role) VALUES($1,$2,$3,$4) RETURNING id,name,email,role",
        [args.name, args.email, hash, args.role]
      );
      return res.rows[0];
    },

    login: async (_, { email, password }) => {
      const res = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
      if (!res.rows.length) throw new Error("User not found");

      const valid = await bcrypt.compare(password, res.rows[0].password);
      if (!valid) throw new Error("Invalid password");

      const token = jwt.sign(
        { id: res.rows[0].id, role: res.rows[0].role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      return { token };
    }
  }
};
