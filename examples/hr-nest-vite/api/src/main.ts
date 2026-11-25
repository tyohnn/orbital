import "reflect-metadata";

import { Module } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";

import { Db } from "./db";
import { HrController } from "./hr.controller";

@Module({ controllers: [HrController], providers: [Db] })
class AppModule
{
}

async function main(): Promise<void>
{
    const app = await NestFactory.create(AppModule, { logger: ["error", "warn"] });
    // router 는 경로를 자르지 않고 넘긴다. 선언의 `path = "/api"` 와 같은 머리를 둔다
    app.setGlobalPrefix("api");
    app.enableShutdownHooks();
    await app.listen(Number(process.env.PORT), process.env.HOST ?? "127.0.0.1");
}

void main();
