// Test Poseidon hypotheses for public signal [0].
import { buildPoseidon } from "circomlibjs";
const poseidon = await buildPoseidon();
const F = poseidon.F;
const target = "18792532188877946924559435975245477428449971206446004025933816523604889133865";
const taskId = 12345, salt = 999;
const tests = {
  "poseidon([taskId, salt])": [taskId, salt],
  "poseidon([salt, taskId])": [salt, taskId],
  "poseidon([taskId])": [taskId],
  "poseidon([salt])": [salt],
  "poseidon([taskId, salt, 1])": [taskId, salt, 1],
  "poseidon([1, taskId, salt])": [1, taskId, salt],
  "poseidon([taskId, salt, 500])": [taskId, salt, 500],
};
for (const [name, inputs] of Object.entries(tests)) {
  const h = poseidon(inputs);
  const s = F.toString(h);
  console.log(`${name} => ${s} ${s === target ? "  <<< MATCH" : ""}`);
}
process.exit(0);
