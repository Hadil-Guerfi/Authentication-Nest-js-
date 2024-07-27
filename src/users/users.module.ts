import { UsersController } from './usersController';
import { UserService } from './users.service';
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';

@Module({
  controllers: [UsersController],
  providers: [UserService],
  imports: [TypeOrmModule.forFeature([User])],
  exports:[UserService,TypeOrmModule]
})
export class UsersModule {}
