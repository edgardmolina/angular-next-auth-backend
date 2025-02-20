import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';

//import { CreateUserDto } from './dto/create-user.dto';
//import { UpdateAuthDto } from './dto/update-auth.dto';
//import { LoginDto } from './dto/login.dto';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response';
import { User } from './entities/user.entity';



@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    //console.log( createAuthDto ) ;
    return this.authService.create(createUserDto);
  }

  @Post( '/login' )
  login( @Body() loginDto : LoginDto ) {
    //return 'Login works!';
    return this.authService.login( loginDto );
  }

  @Post( '/register' )
  register( @Body() registerDto : RegisterUserDto ) {
    //return 'Login works!';
    return this.authService.register( registerDto );
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() req : Request ) {
    //console.log( req );
    //const user = req[ 'user' ];
    //return user;
    return this.authService.findAll();
  }
  
  //LoginResponse
  @UseGuards( AuthGuard )
  @Get( 'check-token' )
  checkToken( @Request() req : Request ) : LoginResponse {
    //return ( '¡Hola Mundo!' );
    const user = req[ 'user' ] as User;
    return {
      user,
      token : this.authService.getJwtToken( { id : user._id } ),
    }
  }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
}
